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
  def objects = List(Group0Var209, Group0Var210, Group0Var254, Group0Var255)
  def group: Byte = 0
  def desc: String = "Device Attributes"
  def isEventGroup: Boolean = false
}
object Group0Var209 extends ClassData(Group0, 209.toByte, "Secure Authentication Version")
object Group0Var210 extends ClassData(Group0, 210.toByte, "Security Statistics Per Association")
object Group0Var254 extends ClassData(Group0, 254.toByte, "All Attributes Request")
object Group0Var255 extends ClassData(Group0, 255.toByte, "List Of Attribute Variations")
