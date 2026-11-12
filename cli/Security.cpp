// Licensed under the Apache License, Version 2.0. See LICENSE in the project root.
#include "Security.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <vector>
#ifdef CLI_SA
#include <opendnp3/auth/WindowsAuthenticationCredentials.h>
#include "auth/UpdateKeyFunctions.h"
#include "crypto/CryptoProvider.h"
#include <windows.h>
#include <wincred.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <io.h>
#include <fcntl.h>
#endif
namespace diagnostic
{
using namespace opendnp3;
namespace
{
uint32_t Number(const std::string& text, uint32_t max)
{
    size_t n = 0;
    if (text.empty() || text[0] == '-') throw std::runtime_error("Invalid numeric option");
    const auto value = std::stoull(text, &n);
    if (n != text.size() || value > max) throw std::runtime_error("Numeric option out of range");
    return static_cast<uint32_t>(value);
}
uint32_t PositiveMilliseconds(const std::string& text)
{
    const auto value = Number(text, 120000);
    if (!value) throw std::runtime_error("Timeout must be in the range 1..120000 ms");
    return value;
}
bool SafeName(const std::string& name)
{
    return !name.empty() && name.size() <= 32 && std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'; });
}
uint64_t UTC()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
class Policy final : public IAuthenticationAuthorization
{
    const uint16_t association;
    const bool deny;
public:
    Policy(uint16_t a, bool d) : association(a), deny(d) {}
    bool IsAuthorized(uint16_t a, uint16_t, uint8_t function, const uint8_t*, size_t) const override
    { return a == association && !(deny && function >= 3 && function <= 6); }
};
#ifdef CLI_SA
using ser4cpp::rseq_t;
using ser4cpp::wseq_t;
template<size_t N> rseq_t Read(const std::array<uint8_t, N>& a) { return {a.data(), a.size()}; }
template<size_t N> wseq_t Write(std::array<uint8_t, N>& a) { return {a.data(), a.size()}; }
std::wstring Wide(const std::string& text) { return std::wstring(text.begin(), text.end()); }
std::wstring Prefix(const Options& o, const char* owner)
{
    return L"DNP3-EXTRA/TEST/" + Wide(o.profile) + L"/" + Wide(owner);
}
struct Secret
{
    std::array<uint8_t, 2048> bytes{};
    size_t size = 0;
    ~Secret() { crypto::Clear(Write(bytes)); }
    rseq_t View() const { return {bytes.data(), size}; }
};
bool LoadSecret(const std::wstring& target, uint8_t* output, size_t capacity, size_t& size)
{
    size = 0;
    PCREDENTIALW value = nullptr;
    if (!CredReadW(target.c_str(), CRED_TYPE_GENERIC, 0, &value)) return false;
    const bool valid = value->CredentialBlobSize <= capacity && value->CredentialBlobSize > 0;
    if (valid) { size = value->CredentialBlobSize; std::copy_n(value->CredentialBlob, size, output); }
    SecureZeroMemory(value->CredentialBlob, value->CredentialBlobSize);
    CredFree(value);
    return valid;
}
void Save(const std::wstring& target, rseq_t bytes)
{
    CREDENTIALW credential{};
    credential.Type = CRED_TYPE_GENERIC; credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
    credential.TargetName = const_cast<wchar_t*>(target.c_str());
    credential.CredentialBlob = const_cast<BYTE*>(static_cast<const uint8_t*>(bytes));
    credential.CredentialBlobSize = static_cast<DWORD>(bytes.length());
    if (!CredWriteW(&credential, 0)) throw std::runtime_error("Test Credential Manager write failed");
}
uint8_t ProfileMethod(const Options& o, bool ready = true)
{
    Secret marker;
    if (!LoadSecret(Prefix(o, "manifest"), marker.bytes.data(), marker.bytes.size(), marker.size)
        || marker.size != 4 || (marker.bytes[0] != 2 && (ready || marker.bytes[0] != 1))
        || (uint16_t(marker.bytes[1]) | uint16_t(marker.bytes[2]) << 8) != o.association) return 0;
    return marker.bytes[3] == 4 || marker.bytes[3] == 68 ? marker.bytes[3] : 0;
}
bool Marked(const Options& o) { return ProfileMethod(o) != 0; }
class ProfileLease
{
    HANDLE mutex = nullptr;
public:
    ProfileLease(const Options& o, const char* owner)
    {
        const auto name = L"Global\\DNP3-EXTRA-TEST-" + Wide(o.profile) + L"-" + Wide(owner);
        mutex = CreateMutexW(nullptr, TRUE, name.c_str());
        const auto error = GetLastError();
        if (!mutex || error == ERROR_ALREADY_EXISTS)
        {
            if (mutex) CloseHandle(mutex);
            throw std::runtime_error("TEST credential namespace already in use; stop the owning process first");
        }
    }
    ~ProfileLease() { CloseHandle(mutex); }
    ProfileLease(const ProfileLease&) = delete;
    ProfileLease& operator=(const ProfileLease&) = delete;
};
class Trust final : public IUpdateKeyTrust
{
    Options options;
    bool Read(const char* name, uint16_t a, uint8_t* output, size_t capacity, size_t& size)
    { return a == options.association && LoadSecret(Prefix(options, "outstation") + L"/" + Wide(name), output, capacity, size); }
public:
    explicit Trust(const Options& o) : options(o) {}
    bool ReadCertificationKey(uint16_t a, uint8_t* output, size_t capacity) override
    { size_t size = 0; return Read("bc", a, output, capacity, size) && size == capacity; }
    bool ReadAuthorityPublicKey(uint16_t a, uint8_t* p, size_t c, size_t& s) override { return Read("authority-public", a, p, c, s); }
    bool ReadOutstationPrivateKey(uint16_t a, uint8_t* p, size_t c, size_t& s) override { return Read("rsa-private", a, p, c, s); }
};

std::vector<uint8_t> ReadBounded(const std::string& path, size_t limit)
{
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    const auto size = input.tellg();
    if (size <= 0 || static_cast<uint64_t>(size) > limit) return {};
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    input.seekg(0);
    if (!input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()))) return {};
    return bytes;
}

class HostCertificatePolicy final : public IUserCertificatePolicy, public IUpdateKeyTrust, public IUpdateKeySource
{
    struct User
    {
        std::string name, keyReference;
        std::vector<uint8_t> subject;
    };
    std::map<std::string, std::string> settings;
    std::vector<User> users;
    const uint16_t association;
    const std::string directory;

    std::string Path(const std::string& value) const
    {
        if (value.empty() || value[0] == '/' || value[0] == '\\' || (value.size() >= 2 && value[1] == ':'))
            return value;
        return directory + value;
    }
    std::vector<uint8_t> File(const char* key, size_t limit) const
    {
        return ReadBounded(Path(Value(key)), limit);
    }

public:
    explicit HostCertificatePolicy(const Options& options)
        : association(options.association),
          directory(options.saTrustManifest.substr(0, options.saTrustManifest.find_last_of("/\\") + 1))
    {
        const auto manifest = ReadBounded(options.saTrustManifest, 16384);
        if (manifest.empty()) throw std::runtime_error("Cannot read SA trust manifest");
        std::istringstream input(std::string(manifest.begin(), manifest.end()));
        for (std::string line; std::getline(input, line);)
        {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty() || line[0] == '#') continue;
            const auto split = line.find('=');
            if (split == std::string::npos || split == 0 || split + 1 == line.size()
                || line.find('\0') != std::string::npos) throw std::runtime_error("Invalid SA trust manifest line");
            const auto key = line.substr(0, split);
            const auto value = line.substr(split + 1);
            if (key == "user")
            {
                const auto first = value.find('|');
                if (first == std::string::npos || users.size() >= MAX_AUTHENTICATION_USERS)
                    throw std::runtime_error("Invalid SA trust manifest user mapping");
                const auto second = value.find('|', first + 1);
                auto name = value.substr(0, first);
                if (name == "Common") name.push_back('\0');
                if (!updatekeys::ValidName({reinterpret_cast<const uint8_t*>(name.data()), name.size()}))
                    throw std::runtime_error("Invalid SA trust manifest DNP user name");
                const auto subject = ReadBounded(Path(value.substr(first + 1, second - first - 1)), MAX_USER_CERTIFICATE_SIZE);
                if (subject.empty() || std::any_of(users.begin(), users.end(), [&](const User& entry) {
                        return entry.name == name || entry.subject == subject;
                    })) throw std::runtime_error("Unreadable or duplicate SA subject mapping");
                users.push_back({std::move(name), second == std::string::npos ? "" : value.substr(second + 1), subject});
            }
            else
            {
                const std::string fields[] = {"policy","association","aor","ca","crl","aa","aa-ca","aa-crl","acrl",
                    "outstation-name","rsa-private-ref","rsa-public","recheck-ms","legacy-authority-public","user-capacity"};
                if (std::find(std::begin(fields), std::end(fields), key) == std::end(fields)
                    || !settings.emplace(key, value).second) throw std::runtime_error("Unknown or duplicate SA trust field");
            }
        }
        if (Value("policy") != "IEC62351-8" || Number(Value("association"), 65535) != association
            || Value("aor").empty() || Value("aor").size() > 64 || users.empty()
            || Value("ca").empty() || Value("crl").empty())
            throw std::runtime_error("SA trust manifest requires matching association, IEC62351-8, AoR, CA, CRL and users");
        const auto& name = Value("outstation-name");
        if (!updatekeys::ValidName({reinterpret_cast<const uint8_t*>(name.data()), name.size()}))
            throw std::runtime_error("SA trust manifest requires a valid outstation name");
        const auto aaFields = !Value("aa").empty() + !Value("aa-ca").empty()
            + !Value("aa-crl").empty() + !Value("acrl").empty();
        if (aaFields && aaFields != 4) throw std::runtime_error("SA trust manifest requires all AA and ACRL fields together");
    }

    std::string Value(const char* key) const
    {
        const auto it = settings.find(key);
        return it == settings.end() ? "" : it->second;
    }
    bool ReadTrust(uint16_t a, UserCertificateTrust& out) override
    {
        if (a != association) return false;
        out = {File("ca", MAX_USER_CERTIFICATE_SIZE), File("crl", 1024 * 1024), Value("aor")};
        return !out.authority.empty() && !out.revocationList.empty();
    }
    bool ReadAttributeTrust(uint16_t a, UserAttributeCertificateTrust& out) override
    {
        if (a != association) return false;
        out = {File("aa", MAX_USER_CERTIFICATE_SIZE), File("aa-ca", MAX_USER_CERTIFICATE_SIZE),
               File("aa-crl", 1024 * 1024), File("acrl", 1024 * 1024)};
        return !out.authority.empty() && !out.issuer.empty() && !out.issuerRevocationList.empty() && !out.revocationList.empty();
    }
    bool ResolveUser(uint16_t a, const uint8_t* subject, size_t length, uint8_t* output, size_t capacity,
                     size_t& size) override
    {
        if (a != association) return false;
        for (const auto& user : users)
        {
            if (user.name.size() <= capacity && user.subject.size() == length
                && std::equal(user.subject.begin(), user.subject.end(), subject))
            {
                size = user.name.size();
                std::copy(user.name.begin(), user.name.end(), output);
                return true;
            }
        }
        return false;
    }
    bool ReadCertificationKey(uint16_t, uint8_t*, size_t) override { return false; }
    bool ReadAuthorityPublicKey(uint16_t a, uint8_t* output, size_t capacity, size_t& size) override
    {
        const auto publicKey = File("legacy-authority-public", capacity);
        if (a != association || publicKey.empty()) return false;
        std::copy(publicKey.begin(), publicKey.end(), output);
        size = publicKey.size();
        return true;
    }
    bool ReadOutstationPrivateKey(uint16_t a, uint8_t* output, size_t capacity, size_t& size) override
    {
        return a == association && LoadSecret(Wide(Value("rsa-private-ref")), output, capacity, size);
    }
    bool GetKey(uint16_t, const uint8_t*, size_t, const uint8_t*, const uint8_t*, uint32_t,
                uint16_t, uint8_t*, uint8_t*, size_t, size_t&) override { return false; }
    bool GetAsymmetricKey(uint16_t a, const uint8_t* name, size_t length, uint8_t* key, uint8_t* secret,
                          size_t capacity, size_t& size, uint8_t* publicKey, size_t publicCapacity,
                          size_t& publicSize) override
    {
        if (a != association) return false;
        for (const auto& user : users)
        {
            if (user.name.size() != length || !std::equal(user.name.begin(), user.name.end(), name)) continue;
            const auto peer = File("rsa-public", publicCapacity);
            if (peer.empty() || user.keyReference.empty()
                || !LoadSecret(Wide(user.keyReference), secret, capacity, size)) return false;
            std::copy(peer.begin(), peer.end(), publicKey);
            publicSize = peer.size();
            return crypto::GenerateRandom({key, 32}) == crypto::Result::OK;
        }
        return false;
    }
};
// Same executable, private anonymous stdin/stdout pipes. This is an explicit
// localhost TEST authority, not a production authority transport or wire codec.
// No authority private key or BC is read in the Master process.
struct AuthorityInput
{
    uint32_t magic = 0x44544B31, scs = 0, ksq = 0;
    uint16_t association = 0, user = 0, role = 0, days = 0, nameSize = 0;
    uint8_t kind = 0, method = 4, operation = 0;
    std::array<uint8_t, 128> name{};
    std::array<uint8_t, 32> ra{}, rb{};
};
struct AuthorityOutput
{
    uint32_t magic = 0;
    uint16_t publicSize = 0, cipherSize = 0;
    uint8_t certificationSize = 0;
    std::array<uint8_t, 1024> publicKey{};
    std::array<uint8_t, 72> certification{};
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 208> cipher{};
    ~AuthorityOutput() { crypto::Clear(Write(key)); }
};
struct Handle
{
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
bool Transfer(HANDLE pipe, void* buffer, size_t size, bool write)
{
    auto* next = static_cast<uint8_t*>(buffer);
    while (size)
    {
        DWORD done = 0;
        const bool ok = write ? WriteFile(pipe, next, static_cast<DWORD>(size), &done, nullptr)
                              : ReadFile(pipe, next, static_cast<DWORD>(size), &done, nullptr);
        if (!ok || !done) return false;
        size -= done; next += done;
    }
    return true;
}
bool CallAuthority(const Options& o, AuthorityInput& input, AuthorityOutput& output)
{
    if (!o.testOnly || !Marked(o)) return false;
    wchar_t exe[32768]{};
    const auto length = GetModuleFileNameW(nullptr, exe, 32768);
    if (!length || length >= 32768) return false;
    std::wstring command = L"\"" + std::wstring(exe) + L"\" authority-worker --test-only --profile " + Wide(o.profile)
        + L" --association " + std::to_wstring(o.association);
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    Handle childIn, parentIn, parentOut, childOut;
    if (!CreatePipe(&childIn.value, &parentIn.value, &attributes, 0)
        || !CreatePipe(&parentOut.value, &childOut.value, &attributes, 0)) return false;
    if (!SetHandleInformation(parentIn.value, HANDLE_FLAG_INHERIT, 0)
        || !SetHandleInformation(parentOut.value, HANDLE_FLAG_INHERIT, 0)) return false;
    SIZE_T attributeSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeSize);
    std::vector<uint8_t> storage(attributeSize);
    auto* attributesList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if (!InitializeProcThreadAttributeList(attributesList, 1, 0, &attributeSize)) return false;
    STARTUPINFOEXW startup{}; startup.StartupInfo.cb = sizeof(startup); startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = childIn.value; startup.StartupInfo.hStdOutput = childOut.value; startup.StartupInfo.hStdError = childOut.value;
    startup.lpAttributeList = attributesList;
    HANDLE inherited[] = {childIn.value, childOut.value};
    PROCESS_INFORMATION process{};
    const bool created = UpdateProcThreadAttribute(attributesList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inherited, sizeof(inherited), nullptr, nullptr)
        && CreateProcessW(exe, &command[0], nullptr, nullptr, TRUE, CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            nullptr, nullptr, &startup.StartupInfo, &process);
    DeleteProcThreadAttributeList(attributesList);
    if (!created) return false;
    Handle ownedProcess{process.hProcess}, ownedThread{process.hThread};
    CloseHandle(childIn.value); childIn.value = nullptr;
    CloseHandle(childOut.value); childOut.value = nullptr;
    if (!Transfer(parentIn.value, &input, sizeof(input), true)) { TerminateProcess(process.hProcess, 1); return false; }
    // Both frames fit in the anonymous-pipe buffer. Wait bounds child execution
    // before reading, so an unavailable authority cannot hang the stack strand.
    if (WaitForSingleObject(process.hProcess, 10000) != WAIT_OBJECT_0)
    { TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, 1000); return false; }
    DWORD code = 1;
    return GetExitCodeProcess(process.hProcess, &code) && code == 0
        && Transfer(parentOut.value, &output, sizeof(output), false) && output.magic == input.magic;
}
std::string CredentialName(const uint8_t* name, size_t size)
{
    if (size == 7 && std::equal(name, name + 7, reinterpret_cast<const uint8_t*>("Common"))) return "Common";
    const std::string text(reinterpret_cast<const char*>(name), size);
    if (text != "operator" && text != "engineer" && text != "guest") throw std::runtime_error("Test authority identity is not provisioned");
    return text;
}
class Source final : public IUpdateKeySource
{
    Options options;
public:
    explicit Source(const Options& o) : options(o) {}
    bool GetKey(uint16_t a, const uint8_t* name, size_t nameSize, const uint8_t* ra, const uint8_t* rb,
                uint32_t sequence, uint16_t user, uint8_t* key, uint8_t* encrypted, size_t capacity, size_t& size) override
    {
        size = 0;
        if (nameSize > 128 || a != options.association) return false;
        AuthorityInput request; request.kind = 1; request.association = a; request.user = user;
        request.ksq = sequence; request.nameSize = static_cast<uint16_t>(nameSize);
        std::copy_n(name, nameSize, request.name.begin()); std::copy_n(ra, 32, request.ra.begin()); std::copy_n(rb, 32, request.rb.begin());
        AuthorityOutput reply;
        if (!CallAuthority(options, request, reply) || reply.cipherSize > reply.cipher.size() || reply.cipherSize > capacity || reply.cipherSize < 24) return false;
        std::copy(reply.key.begin(), reply.key.end(), key);
        std::copy_n(reply.cipher.data(), reply.cipherSize, encrypted); size = reply.cipherSize; return true;
    }
    bool GetAsymmetricKey(uint16_t a, const uint8_t* name, size_t n, uint8_t* key,
        uint8_t* secret, size_t capacity, size_t& size, uint8_t* pub, size_t pc, size_t& ps) override
    {
        if (a != options.association || !Marked(options)) return false;
        const auto identity = CredentialName(name, n);
        return LoadSecret(Prefix(options, "master") + L"/private-" + Wide(identity), secret, capacity, size)
            && LoadSecret(Prefix(options, "master") + L"/rsa-public", pub, pc, ps)
            && crypto::GenerateRandom({key, 32}) == crypto::Result::OK;
    }
};
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Context = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
void Export(EVP_PKEY* key, const std::wstring& privateTarget, const std::wstring& publicTarget)
{
    Secret secret, pub;
    const int a = i2d_PrivateKey(key, nullptr), b = i2d_PUBKEY(key, nullptr);
    if (a <= 0 || a > secret.bytes.size() || b <= 0 || b > pub.bytes.size()) throw std::runtime_error("Test key encoding failed");
    auto* x = secret.bytes.data(); auto* y = pub.bytes.data();
    if (i2d_PrivateKey(key, &x) != a || i2d_PUBKEY(key, &y) != b) throw std::runtime_error("Test key encoding failed");
    secret.size = a; pub.size = b; Save(privateTarget, secret.View()); Save(publicTarget, pub.View());
}
void EraseProfile(const Options& o)
{
    auto erase = [](const std::wstring& target) {
        if (!CredDeleteW(target.c_str(), CRED_TYPE_GENERIC, 0) && GetLastError() != ERROR_NOT_FOUND)
            throw std::runtime_error("TEST credential cleanup failed");
    };
    for (const auto* owner : {"master", "outstation"})
        for (unsigned user = 1; user <= 4; ++user)
        {
            const auto base = Prefix(o, owner) + L"/" + std::to_wstring(o.association) + L"/" + std::to_wstring(user);
            for (const auto* suffix : {L"", L"/remote0", L"/remote1"}) erase(base + suffix);
        }
    erase(Prefix(o, "master") + L"/rsa-public"); erase(Prefix(o, "outstation") + L"/rsa-private");
    erase(Prefix(o, "authority") + L"/bc"); erase(Prefix(o, "outstation") + L"/bc");
    erase(Prefix(o, "authority") + L"/dsa-private"); erase(Prefix(o, "outstation") + L"/authority-public");
    for (const auto* identity : {"Common", "operator", "engineer", "guest"})
    {
        erase(Prefix(o, "master") + L"/private-" + Wide(identity));
        erase(Prefix(o, "authority") + L"/public-" + Wide(identity));
    }
    erase(Prefix(o, "manifest"));
}
#endif
}
Options ParseOptions(int argc, char** argv)
{
    if (argc < 2) throw std::runtime_error("Usage: dnp3-cli master|outstation|test-provision|test-cleanup|test-tls [options]");
    Options o; o.role = argv[1];
    o.local = o.role == "master" ? 1 : 10;
    o.remote = o.role == "master" ? 10 : 1;
    bool explicitPort = false;
    for (int n = 2; n < argc; ++n)
    {
        const std::string option = argv[n];
        if (option == "--test-only") { o.testOnly = true; continue; }
        if (option == "--trust-system-time") { o.trustedTime = true; continue; }
        if (option == "--aggressive") { o.aggressive = true; continue; }
        if (option == "--deny-controls") { o.denyControls = true; continue; }
        if (option == "--unsolicited") { o.unsolicited = true; continue; }
        if (option == "--command-events") { o.commandEvents = true; continue; }
        if (option == "--control-q17")
        {
            if (o.role != "master") throw std::runtime_error("--control-q17 requires master");
            o.prefer8BitControlQualifiers = true;
            continue;
        }
        if (option == "--event-q17")
        {
            if (o.role != "outstation") throw std::runtime_error("--event-q17 requires outstation");
            o.prefer8BitEventQualifiers = true;
            continue;
        }
        if (option == "--rtu-io-profile") { o.rtuIoProfile = true; continue; }
        if (option == "--trace") { o.trace = true; continue; }
        if (option == "--tls") { o.tls = true; continue; }
        if (option == "--expired-test-certificate") { o.expiredTestCertificate = true; continue; }
        if (option == "--self-signed-test-certificate") { o.selfSignedTestCertificate = true; continue; }
        if (option == "--intermediate-test-ca")
        {
            if (o.role != "test-tls") throw std::runtime_error("--intermediate-test-ca requires test-tls");
            o.intermediateTestCA = true;
            continue;
        }
        if (++n == argc) throw std::runtime_error("Missing option value");
        const std::string value = argv[n];
        if (option == "--host") o.host = value;
        else if (option == "--port") { o.port = static_cast<uint16_t>(Number(value, 65535)); explicitPort = true; }
        else if (option == "--local") o.local = static_cast<uint16_t>(Number(value, 65519));
        else if (option == "--remote") o.remote = static_cast<uint16_t>(Number(value, 65519));
        else if (option == "--association") o.association = static_cast<uint16_t>(Number(value, 65535));
        else if (option == "--user") o.user = static_cast<uint16_t>(Number(value, 65535));
        else if (option == "--response-ms") o.responseMs = Number(value, 120000);
        else if (option == "--link-confirm")
        {
            if (value == "never") o.linkConfirmMode = LinkConfirmMode::Never;
            else if (value == "always") o.linkConfirmMode = LinkConfirmMode::Always;
            else if (value == "multi-frame") o.linkConfirmMode = LinkConfirmMode::MultiFrame;
            else throw std::runtime_error("--link-confirm requires never, always or multi-frame");
        }
        else if (option == "--link-retries") o.linkRetries = static_cast<uint8_t>(Number(value, 5));
        else if (option == "--link-timeout-ms") o.linkTimeoutMs = PositiveMilliseconds(value);
        else if (option == "--rx-fragment-timeout-ms") o.rxFragmentTimeoutMs = PositiveMilliseconds(value);
        else if (option == "--complete-response-ms")
        {
            if (o.role != "master") throw std::runtime_error("--complete-response-ms requires master");
            o.completeResponseMs = PositiveMilliseconds(value);
        }
        else if (option == "--sol-confirm-ms" || option == "--unsol-confirm-ms")
        {
            if (o.role != "outstation") throw std::runtime_error("Application confirm timeouts require outstation");
            (option == "--sol-confirm-ms" ? o.solConfirmMs : o.unsolConfirmMs) = PositiveMilliseconds(value);
        }
        else if (option == "--unsol-retries")
        {
            if (o.role != "outstation") throw std::runtime_error("--unsol-retries requires outstation");
            o.unsolRetries = static_cast<uint8_t>(Number(value, 5));
            if (!o.unsolRetries) throw std::runtime_error("--unsol-retries requires 1..5");
        }
        else if (option == "--binary-event-time")
        {
            if (o.role != "outstation" || (value != "absolute" && value != "relative"))
                throw std::runtime_error("--binary-event-time requires outstation and absolute or relative");
            o.relativeBinaryTime = value == "relative";
        }
        else if (option == "--rx-fragment-bytes") o.rxFragmentBytes = Number(value, 65535);
        else if (option == "--tx-fragment-bytes") o.txFragmentBytes = Number(value, 65535);
        else if (option == "--reply-ms") o.replyMs = Number(value, 120000);
        else if (option == "--renewal-ms") o.renewalMs = Number(value, 7200000);
        else if (option == "--message-count") o.messageCount = Number(value, 0xFFFFFFFF);
        else if (option == "--rtu-crob-latch")
        {
            const auto index = Number(value, static_cast<uint32_t>(o.rtuCrobLatches.size() - 1));
            if (o.rtuCrobTwoOutputs.test(index) || o.rtuCrobActivation.test(index))
                throw std::runtime_error("Conflicting CROB models for point");
            if (o.rtuCrobLatches.test(index))
                throw std::runtime_error("Duplicate --rtu-crob-latch index");
            o.rtuCrobLatches.set(index);
        }
        else if (option == "--rtu-crob-two-output" || option == "--rtu-crob-activation")
        {
            const bool activation = option == "--rtu-crob-activation";
            const auto separator = value.find(':');
            if (separator == std::string::npos ||
                value.find(':', separator + 1) != std::string::npos)
                throw std::runtime_error("Expected " + option + " <index>:<pulse-ms>");
            uint32_t index = 0;
            uint32_t pulseMs = 0;
            try
            {
                index = Number(value.substr(0, separator), 9);
                pulseMs = PositiveMilliseconds(value.substr(separator + 1));
            }
            catch (const std::invalid_argument&)
            {
                throw std::runtime_error("Invalid " + option + " index or pulse duration");
            }
            if (o.rtuCrobLatches.test(index)
                || (activation ? o.rtuCrobTwoOutputs.test(index) : o.rtuCrobActivation.test(index)))
                throw std::runtime_error("Conflicting CROB models for point");
            auto& points = activation ? o.rtuCrobActivation : o.rtuCrobTwoOutputs;
            if (points.test(index))
                throw std::runtime_error("Duplicate " + option + " index");
            points.set(index);
            o.rtuCrobPulseMs[index] = pulseMs;
        }
        else if (option == "--auth") o.auth = value;
        else if (option == "--profile") o.profile = value;
        else if (option == "--credentials") o.credentials = value;
        else if (option == "--sa-trust") o.saTrustManifest = value;
        else if (option == "--ca") o.ca = value;
        else if (option == "--crl") { if (value.empty()) throw std::runtime_error("--crl requires a PEM path"); o.crl = value; }
        else if (option == "--crl-check-hours")
        {
            o.crlCheckHours = static_cast<uint16_t>(Number(value, 65535));
            if (!o.crlCheckHours) throw std::runtime_error("--crl-check-hours must be at least 1");
        }
        else if (option == "--cert") o.cert = value;
        else if (option == "--key") o.key = value;
        else if (option == "--peer-name") o.peerName = value;
        else if (option == "--tls-version") o.tlsVersion = value;
        else if (option == "--ciphers") o.ciphers = value;
        else if (option == "--suites") o.suites = value;
        else if (option == "--directory") o.directory = value;
        else throw std::runtime_error("Unknown option: " + option);
    }
    if (!o.profile.empty() && !SafeName(o.profile)) throw std::runtime_error("Profile must be 1..32 ASCII letters/digits/hyphens");
    // Credential Manager targets are case-insensitive; lease names must have
    // the same identity so case changes cannot create a second owner.
    for (auto& ch : o.profile) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch + ('a' - 'A'));
    if (o.auth != "compat" && o.auth != "method4" && o.auth != "method68") throw std::runtime_error("Unknown authentication mode");
    if (!o.saTrustManifest.empty() && (o.auth != "method68" || o.credentials.empty() || !o.profile.empty()
        || (o.role != "master" && o.role != "outstation")))
        throw std::runtime_error("--sa-trust requires a Method68 master or outstation, --credentials, and no TEST profile");
    // A zero security Reply Timer expires immediately; responseMs is the separate
    // application/task timeout and still cannot be zero.
    if (!o.port || !o.user || !o.responseMs || !o.renewalMs || !o.messageCount) throw std::runtime_error("Zero port/user/timeout/count is unsupported");
    if (!o.profile.empty() && o.host != "127.0.0.1") throw std::runtime_error("TEST credential profiles require localhost 127.0.0.1");
    if (!o.crl.empty() && (!o.tls || (o.role != "master" && o.role != "outstation")))
        throw std::runtime_error("--crl requires a TLS master or outstation");
    if (o.crlCheckHours && o.crl.empty())
        throw std::runtime_error("--crl-check-hours requires --crl");
    if (o.rtuIoProfile && o.role != "master" && o.role != "outstation")
        throw std::runtime_error("--rtu-io-profile requires master or outstation");
    if ((o.rtuCrobLatches.any() || o.rtuCrobTwoOutputs.any() || o.rtuCrobActivation.any()) &&
        (o.role != "outstation" || !o.rtuIoProfile || !o.testOnly || o.auth == "compat"))
        throw std::runtime_error("RTU CROB models require an RTU outstation, --test-only and SA");
    if (o.linkRetries && o.linkConfirmMode == LinkConfirmMode::Never)
        throw std::runtime_error("Nonzero --link-retries requires a confirmed link mode");
    if (o.unsolRetries && !o.unsolicited)
        throw std::runtime_error("--unsol-retries requires --unsolicited");
    if (o.rxFragmentBytes < 250 || o.txFragmentBytes < 250)
        throw std::runtime_error("Diagnostic fragment size must be 250..65535 bytes");
    if (o.tls && !explicitPort) o.port = 19999;
    return o;
}
AuthenticationConfig Authentication(const Options& o, bool master)
{
    AuthenticationConfig config;
    if (o.auth == "compat") { config.mode = AuthenticationConfig::Mode::COMPATIBILITY; return config; }
#ifdef CLI_SA
    if (!o.trustedTime) throw std::runtime_error("SA requires an explicitly trusted clock: --trust-system-time");
    if (o.profile.empty() && o.credentials.empty()) throw std::runtime_error("SA requires --credentials or a TEST profile");
    if (o.profile.empty() && o.auth == "method68" && o.saTrustManifest.empty())
        throw std::runtime_error("Method68 requires --sa-trust or the explicit TEST profile");
    const auto host = o.saTrustManifest.empty() ? nullptr : std::make_shared<HostCertificatePolicy>(o);
    if (host && !master && host->Value("rsa-private-ref").empty())
        throw std::runtime_error("SA trust manifest requires rsa-private-ref for the Outstation");
    config.association = o.association; config.renewalIntervalMs = o.renewalMs;
    config.renewalMessageCount = o.messageCount; config.replyTimeoutMs = o.replyMs;
    config.aggressiveTransmit = config.aggressiveReceive = o.aggressive;
    const auto* owner = master ? "master" : "outstation";
    if (!o.profile.empty() && !o.testOnly) throw std::runtime_error("TEST profile requires explicit --test-only");
    auto lease = o.profile.empty() ? nullptr : std::make_shared<ProfileLease>(o, owner);
    if (lease)
    {
        const auto method = ProfileMethod(o);
        if (!method) throw std::runtime_error("Missing explicitly provisioned TEST profile");
        if (o.auth == "method68" && method != 68) throw std::runtime_error("Method68 requires Method68 TEST provisioning");
    }
    config.credentials = std::shared_ptr<WindowsAuthenticationCredentials>(new WindowsAuthenticationCredentials(
        o.profile.empty() ? Wide(o.credentials) : Prefix(o, owner), [](uint64_t& now) { now = UTC(); return now != 0; }),
        [lease](WindowsAuthenticationCredentials* value) { delete value; });
    config.authorization = std::make_shared<Policy>(o.association, o.denyControls);
    config.remoteUpdateKeys = host || !o.profile.empty(); config.userCapacity = 4;
    config.allowMethod68 = o.auth == "method68";
    const std::string name = host ? host->Value("outstation-name") : "DNP3-EXTRA-TEST";
    std::copy(name.begin(), name.end(), config.outstationName.begin()); config.outstationNameSize = static_cast<uint16_t>(name.size());
    if (host)
    {
        UserCertificateTrust identityTrust;
        UserAttributeCertificateTrust attributeTrust;
        if (!host->ReadTrust(o.association, identityTrust)
            || (!host->Value("aa").empty() && !host->ReadAttributeTrust(o.association, attributeTrust)))
            throw std::runtime_error("Unreadable or oversized SA trust certificate or revocation list");
        const auto capacity = Number(host->Value("user-capacity"), MAX_AUTHENTICATION_USERS);
        if (capacity < 2) throw std::runtime_error("SA trust manifest user-capacity must be at least 2");
        config.userCapacity = static_cast<uint16_t>(capacity);
        config.userCertificatePolicy = host;
        const auto interval = host->Value("recheck-ms");
        if (!interval.empty()) config.userCertificateRecheckIntervalMs = Number(interval, UINT32_MAX);
        if (!master) config.updateKeyTrust = host;
    }
    else if (!master && config.remoteUpdateKeys) config.updateKeyTrust = std::make_shared<Trust>(o);
    return config;
#else
    throw std::runtime_error("SA requires a Windows DNP3_SA_CRYPTO build");
#endif
}
UpdateKeyRequest CertificateRequest(const Options& o, const std::string& type, const std::string& path)
{
#ifdef CLI_SA
    if (o.saTrustManifest.empty()) throw std::runtime_error("Certificate relay requires --sa-trust");
    UpdateKeyRequest request;
    request.method = 68;
    if (type == "id") request.certificateType = 1;
    else if (type == "attribute") request.certificateType = 2;
    else throw std::runtime_error("Expected id or attribute certificate");
    request.certificate = ReadBounded(path, MAX_USER_CERTIFICATE_SIZE);
    if (request.certificate.empty()) throw std::runtime_error("Unreadable or oversized DER certificate");
    request.source = std::make_shared<HostCertificatePolicy>(o);
    return request;
#else
    throw std::runtime_error("SA is unavailable in this build");
#endif
}
UpdateKeyRequest AuthorizedRequest(const Options& o, const std::string& op, const std::string& text, uint32_t scs, uint16_t role, uint16_t days)
{
#ifdef CLI_SA
    if (o.auth == "compat" || !o.testOnly || !Marked(o)) throw std::runtime_error("Remote updates require an explicitly provisioned TEST authority");
    const std::string name = text == "Common" ? std::string("Common\0", 7) : text;
    CredentialName(reinterpret_cast<const uint8_t*>(name.data()), name.size());
    UpdateKeyRequest request; request.method = o.auth == "method68" ? 68 : 4;
    std::copy(name.begin(), name.end(), request.name.begin()); request.nameSize = static_cast<uint16_t>(name.size());
    request.source = std::make_shared<Source>(o);
    if (op == "verify") { request.verifyOnly = true; return request; }
    if (op == "change-key") return request;
    AuthorityInput input; input.method = request.method; input.association = o.association;
    input.scs = scs; input.role = role; input.days = days; input.name = request.name; input.nameSize = request.nameSize;
    input.operation = op == "add" ? 1 : op == "delete" ? 2 : op == "change" ? 3 : 0;
    if (!input.operation) throw std::runtime_error("Expected add/change/delete/verify/change-key");
    AuthorityOutput result;
    if (!CallAuthority(o, input, result)) throw std::runtime_error("Test authority unavailable or request denied");
    request.operation = input.operation; request.statusSequence = scs; request.role = role; request.expiryDays = days;
    request.publicKey = result.publicKey; request.publicKeySize = result.publicSize;
    request.certification = result.certification; request.certificationSize = result.certificationSize;
    return request;
#else
    throw std::runtime_error("SA is unavailable in this build");
#endif
}
void PrintUsers(const Options& o, bool master)
{
#ifdef CLI_SA
    if (o.profile.empty()) { std::cout << "User metadata unavailable for legacy credential references\n"; return; }
    WindowsAuthenticationCredentials storage(Prefix(o, master ? "master" : "outstation"));
    for (size_t slot = 0; slot < 4; ++slot)
    {
        UpdateKeyUser user;
        if (!storage.ReadUser(o.association, slot, user)) { std::cout << "USER slot=" << slot << " unavailable\n"; continue; }
        if (!user.nameSize) continue;
        std::cout << "USER number=" << user.user << " active=" << user.active << " role=" << user.role
            << " pending-role=" << user.pending << " pending-key=" << user.havePendingKey
            << " scs=" << user.statusSequence << " expiry-utc-ms=" << user.expiresUnixMs << '\n';
    }
    std::cout.flush();
#endif
}
int AuthorityWorker(const Options& o)
{
#ifdef CLI_SA
    if (!o.testOnly || !Marked(o) || GetFileType(GetStdHandle(STD_INPUT_HANDLE)) != FILE_TYPE_PIPE
        || GetFileType(GetStdHandle(STD_OUTPUT_HANDLE)) != FILE_TYPE_PIPE) return 2;
    _setmode(_fileno(stdin), _O_BINARY); _setmode(_fileno(stdout), _O_BINARY);
    AuthorityInput input; AuthorityOutput output;
    if (!Transfer(GetStdHandle(STD_INPUT_HANDLE), &input, sizeof(input), false) || input.magic != 0x44544B31
        || input.association != o.association || input.nameSize > 128) return 2;
    const auto identity = CredentialName(input.name.data(), input.nameSize);
    Secret authority;
    if (input.kind == 1)
    {
        if (input.method != 4 || !LoadSecret(Prefix(o, "authority") + L"/bc", authority.bytes.data(), authority.bytes.size(), authority.size)
            || authority.size != 32 || crypto::GenerateRandom(Write(output.key)) != crypto::Result::OK) return 2;
        Secret plain; size_t size = 0;
        if (!updatekeys::KeyData({input.name.data(), input.nameSize}, Read(output.key), Read(input.rb), Write(plain.bytes), size)) return 2;
        output.cipherSize = static_cast<uint16_t>(size + 8);
        if (crypto::AES256KeyWrap(authority.View(), {plain.bytes.data(), size},
            {output.cipher.data(), output.cipherSize}) != crypto::Result::OK) return 2;
    }
    else if (input.kind == 0)
    {
        size_t size = 0;
        if (input.method == 68)
        {
            if (!LoadSecret(Prefix(o, "authority") + L"/public-" + Wide(identity), output.publicKey.data(), output.publicKey.size(), size)) return 2;
            output.publicSize = static_cast<uint16_t>(size);
        }
        Group120Var10 status(input.method, input.operation, input.scs, input.role, input.days,
            {input.name.data(), input.nameSize}, {output.publicKey.data(), output.publicSize}, {});
        std::array<uint8_t, 1200> transcript{};
        if (!updatekeys::CertificationData(status, Write(transcript), size)) return 2;
        if (input.method == 4)
        {
            if (!LoadSecret(Prefix(o, "authority") + L"/bc", authority.bytes.data(), authority.bytes.size(), authority.size) || authority.size != 32) return 2;
            output.certificationSize = 16;
            if (crypto::ComputeHMACSHA256(authority.View(), {transcript.data(), size}, {output.certification.data(), 16}) != crypto::Result::OK) return 2;
        }
        else if (input.method == 68)
        {
            if (!LoadSecret(Prefix(o, "authority") + L"/dsa-private", authority.bytes.data(), authority.bytes.size(), authority.size)) return 2;
            size_t signedSize = 0;
            if (crypto::DSASHA256Sign(authority.View(), {transcript.data(), size}, Write(output.certification), signedSize) != crypto::Result::OK) return 2;
            output.certificationSize = static_cast<uint8_t>(signedSize);
        }
        else return 2;
    }
    else return 2;
    output.magic = input.magic;
    return Transfer(GetStdHandle(STD_OUTPUT_HANDLE), &output, sizeof(output), true) ? 0 : 2;
#else
    return 2;
#endif
}
int Provision(const Options& o)
{
#ifdef CLI_SA
    if (!o.testOnly || o.profile.empty()) throw std::runtime_error("Explicit --test-only --profile <unique-name> required");
    ProfileLease master(o, "master"), outstation(o, "outstation");
    if (o.role == "test-cleanup")
    {
        if (!ProfileMethod(o, false)) throw std::runtime_error("Refusing cleanup: no matching TEST manifest");
        EraseProfile(o);
        std::cout << "TEST credentials removed from the exact named namespace; stop both peers before cleanup.\n"; return 0;
    }
    if (Marked(o)) throw std::runtime_error("TEST profile already exists; no overwrite permitted");
    // Refuse to overwrite orphaned credentials, including a partial previous provisioning.
    DWORD count = 0; PCREDENTIALW* existing = nullptr;
    const auto filter = Prefix(o, "");
    if (CredEnumerateW((filter + L"*").c_str(), 0, &count, &existing))
    { CredFree(existing); throw std::runtime_error("TEST namespace is not empty; choose a fresh profile"); }
    if (GetLastError() != ERROR_NOT_FOUND) throw std::runtime_error("Cannot verify empty TEST namespace");
    uint8_t marker[] = {1, static_cast<uint8_t>(o.association), static_cast<uint8_t>(o.association >> 8),
        static_cast<uint8_t>(o.auth == "method68" ? 68 : 4)};
    Save(Prefix(o, "manifest"), {marker, sizeof(marker)});
    try
    {
        Secret bc; bc.size = 32;
        if (crypto::GenerateRandom({bc.bytes.data(), bc.size}) != crypto::Result::OK) throw std::runtime_error("CSPRNG unavailable");
        Save(Prefix(o, "authority") + L"/bc", bc.View()); Save(Prefix(o, "outstation") + L"/bc", bc.View());
        const char* names[] = {"Common", "operator", "engineer"};
        for (size_t n = 0; n < 3; ++n)
        {
            UpdateKeyUser user; user.user = static_cast<uint16_t>(n + 1); user.active = true;
            user.nameSize = static_cast<uint16_t>(std::char_traits<char>::length(names[n]) + (n == 0 ? 1 : 0));
            std::copy_n(names[n], user.nameSize, user.name.begin()); user.role = n == 1 ? 1 : 32768;
            user.expiresUnixMs = UTC() + 86400000;
            if (crypto::GenerateRandom(Write(user.updateKey)) != crypto::Result::OK) throw std::runtime_error("CSPRNG unavailable");
            for (const auto* owner : {"master", "outstation"})
            {
                WindowsAuthenticationCredentials storage(Prefix(o, owner));
                if (!storage.WriteUser(o.association, n, user)) throw std::runtime_error("Test user provisioning failed");
            }
        }
        if (o.auth == "method68")
        {
            Context gen(EVP_PKEY_CTX_new_from_name(nullptr, "DSA", nullptr), EVP_PKEY_CTX_free);
            unsigned p = 2048, q = 256;
            OSSL_PARAM params[] = {OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_PBITS, &p),
                OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_FFC_QBITS, &q), OSSL_PARAM_construct_end()};
            EVP_PKEY* raw = nullptr;
            if (!gen || EVP_PKEY_paramgen_init(gen.get()) <= 0 || EVP_PKEY_CTX_set_params(gen.get(), params) <= 0
                || EVP_PKEY_paramgen(gen.get(), &raw) <= 0) throw std::runtime_error("DSA2048/256 unavailable");
            Key domain(raw, EVP_PKEY_free);
            Context keys(EVP_PKEY_CTX_new_from_pkey(nullptr, domain.get(), nullptr), EVP_PKEY_CTX_free);
            if (!keys || EVP_PKEY_keygen_init(keys.get()) <= 0) throw std::runtime_error("DSA key generator unavailable");
            raw = nullptr;
            if (EVP_PKEY_keygen(keys.get(), &raw) <= 0) throw std::runtime_error("Authority generation failed");
            Key authority(raw, EVP_PKEY_free);
            Export(authority.get(), Prefix(o, "authority") + L"/dsa-private", Prefix(o, "outstation") + L"/authority-public");
            for (const auto* name : {"Common", "operator", "engineer", "guest"})
            {
                raw = nullptr;
                if (EVP_PKEY_keygen(keys.get(), &raw) <= 0) throw std::runtime_error("User key generation failed");
                Key user(raw, EVP_PKEY_free);
                Export(user.get(), Prefix(o, "master") + L"/private-" + Wide(name), Prefix(o, "authority") + L"/public-" + Wide(name));
            }
            Key rsa(EVP_RSA_gen(2048), EVP_PKEY_free);
            if (!rsa) throw std::runtime_error("RSA2048 unavailable");
            Export(rsa.get(), Prefix(o, "outstation") + L"/rsa-private", Prefix(o, "master") + L"/rsa-public");
        }
        marker[0] = 2; Save(Prefix(o, "manifest"), {marker, sizeof(marker)});
    }
    catch (...)
    {
        try { EraseProfile(o); } catch (...) {}
        throw;
    }
    std::cout << "TEST-ONLY profile provisioned in Windows Credential Manager. Initial users: Common=1 operator=2 engineer=3; guest ADD slot=4. Expires in 24 hours.\n";
    return 0;
#else
    throw std::runtime_error("TEST provisioning requires Windows SA crypto");
#endif
}
}
