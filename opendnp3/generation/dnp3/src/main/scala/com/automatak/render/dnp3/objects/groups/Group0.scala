/**
 * Copyright 2013-2020 Automatak, LLC
 *
 * Licensed to Green Energy Corp (www.greenenergycorp.com) and Automatak
 * LLC (www.automatak.com) under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Green Energy Corp and Automatak LLC license
 * this file to you under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.automatak.render.dnp3.objects.groups

import com.automatak.render.dnp3.objects._

// Variable type/length/value attributes use the shared DeviceAttribute parser.
object Group0 extends ObjectGroup {
  def objects = List(
    Group0Var209, Group0Var210, Group0Var211, Group0Var212, Group0Var213,
    Group0Var214, Group0Var215, Group0Var216, Group0Var217, Group0Var218,
    Group0Var219, Group0Var220, Group0Var221, Group0Var222, Group0Var223,
    Group0Var224, Group0Var225, Group0Var226, Group0Var227, Group0Var228,
    Group0Var229, Group0Var230, Group0Var231, Group0Var232, Group0Var233,
    Group0Var234, Group0Var235, Group0Var236, Group0Var237, Group0Var238,
    Group0Var239, Group0Var240, Group0Var241, Group0Var242, Group0Var243,
    Group0Var245, Group0Var246, Group0Var247, Group0Var248, Group0Var249,
    Group0Var250, Group0Var252, Group0Var254, Group0Var255
  )
  def group: Byte = 0
  def desc: String = "Device Attributes"
  def isEventGroup: Boolean = false
}
object Group0Var209 extends ClassData(Group0, 209.toByte, "Secure Authentication Version")
object Group0Var210 extends ClassData(Group0, 210.toByte, "Security Statistics Per Association")
object Group0Var211 extends ClassData(Group0, 211.toByte, "User Specific Attribute Support")
object Group0Var212 extends ClassData(Group0, 212.toByte, "Master Defined Data Set Prototypes")
object Group0Var213 extends ClassData(Group0, 213.toByte, "Outstation Defined Data Set Prototypes")
object Group0Var214 extends ClassData(Group0, 214.toByte, "Master Defined Data Sets")
object Group0Var215 extends ClassData(Group0, 215.toByte, "Outstation Defined Data Sets")
object Group0Var216 extends ClassData(Group0, 216.toByte, "Maximum Binary Outputs Per Request")
object Group0Var217 extends ClassData(Group0, 217.toByte, "Local Timing Accuracy")
object Group0Var218 extends ClassData(Group0, 218.toByte, "Duration Of Timing Accuracy")
object Group0Var219 extends ClassData(Group0, 219.toByte, "Analog Output Event Support")
object Group0Var220 extends ClassData(Group0, 220.toByte, "Maximum Analog Output Index")
object Group0Var221 extends ClassData(Group0, 221.toByte, "Number Of Analog Outputs")
object Group0Var222 extends ClassData(Group0, 222.toByte, "Binary Output Event Support")
object Group0Var223 extends ClassData(Group0, 223.toByte, "Maximum Binary Output Index")
object Group0Var224 extends ClassData(Group0, 224.toByte, "Number Of Binary Outputs")
object Group0Var225 extends ClassData(Group0, 225.toByte, "Frozen Counter Event Support")
object Group0Var226 extends ClassData(Group0, 226.toByte, "Frozen Counter Support")
object Group0Var227 extends ClassData(Group0, 227.toByte, "Counter Event Support")
object Group0Var228 extends ClassData(Group0, 228.toByte, "Maximum Counter Index")
object Group0Var229 extends ClassData(Group0, 229.toByte, "Number Of Counter Points")
object Group0Var230 extends ClassData(Group0, 230.toByte, "Frozen Analog Input Support")
object Group0Var231 extends ClassData(Group0, 231.toByte, "Analog Input Event Support")
object Group0Var232 extends ClassData(Group0, 232.toByte, "Maximum Analog Input Index")
object Group0Var233 extends ClassData(Group0, 233.toByte, "Number Of Analog Input Points")
object Group0Var234 extends ClassData(Group0, 234.toByte, "Double Bit Binary Input Event Support")
object Group0Var235 extends ClassData(Group0, 235.toByte, "Maximum Double Bit Binary Input Index")
object Group0Var236 extends ClassData(Group0, 236.toByte, "Number Of Double Bit Binary Input Points")
object Group0Var237 extends ClassData(Group0, 237.toByte, "Binary Input Event Support")
object Group0Var238 extends ClassData(Group0, 238.toByte, "Maximum Binary Input Index")
object Group0Var239 extends ClassData(Group0, 239.toByte, "Number Of Binary Input Points")
object Group0Var240 extends ClassData(Group0, 240.toByte, "Maximum Transmit Fragment Size")
object Group0Var241 extends ClassData(Group0, 241.toByte, "Maximum Receive Fragment Size")
object Group0Var242 extends ClassData(Group0, 242.toByte, "Manufacturer Software Version")
object Group0Var243 extends ClassData(Group0, 243.toByte, "Manufacturer Hardware Version")
object Group0Var245 extends ClassData(Group0, 245.toByte, "User Assigned Location")
object Group0Var246 extends ClassData(Group0, 246.toByte, "User Assigned ID")
object Group0Var247 extends ClassData(Group0, 247.toByte, "User Assigned Name")
object Group0Var248 extends ClassData(Group0, 248.toByte, "Serial Number")
object Group0Var249 extends ClassData(Group0, 249.toByte, "Subset And Conformance")
object Group0Var250 extends ClassData(Group0, 250.toByte, "Product Name And Model")
object Group0Var252 extends ClassData(Group0, 252.toByte, "Manufacturer Name")
object Group0Var254 extends ClassData(Group0, 254.toByte, "All Attributes Request")
object Group0Var255 extends ClassData(Group0, 255.toByte, "List Of Attribute Variations")
