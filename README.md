# asa_to_palo_converter

ASA to Palo Conversion Tool Using A Python Program Called "asa_to_palo_converter.py"

"Version 3 Demo"

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

ASA to Palo Alto Conversion Script – Feature Summary

✅ ASA Rule Parsing

Converts ASA-style access-list rules to Palo Alto format.

📦 Object & Object-Group Support

Parses ASA object network and object-group network definitions.

Converts them to Palo Alto set address and set address-group commands.

🛡 Rule Generation in CLI Format

Outputs converted rules as set rulebase security CLI commands.

Includes source, destination, service, and action fields.

📁 Panorama XML Export

Optional --xml flag to generate Panorama-compatible XML.

Includes correct Panorama hierarchy with <device-group> and <pre-rulebase> elements.

🏷 Rule Tagging & Descriptions

Tags and comments are added by default (can be disabled via --no-tags).

Custom tag name support using --tag-name.

🖧 Device Group Support

Device group name is customizable with --dg or --device-group.

🔁 Consistent Object References

Re-uses object names consistently across rules and groups.

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Functional Preview of the Script: 

The original ASA config is placed in a .txt file 
(**The ACL name will have to be changed to apply the "from" and "to" name-if directionally
this is the only change that needs to be made in the ASA text file**)

asa_rules.txt (filename can be any name)

object-group network WEB_SERVERS
 network-object host 192.168.3.1
 network-object host 192.168.3.2

access-list INSIDE to OUTSIDE extended permit tcp any object-group WEB_SERVERS eq 80
access-list OUTSIDE to INSIDE extended permit tcp any 200.16.0.21 255.255.255.0 eq 443
access-list INSIDE to OUTSIDE extended permit ip any any

The Python program can show help options using --help

usage: asa_to_palo_converter.py [-h] [--xml] [--dg DEVICE_GROUP] [--no-tags] [--tag-name TAG_NAME] input_file output_file

Convert ASA rules to Palo Alto format.

positional arguments:
  input_file            ASA config input file
  output_file           Output file

options:
  -h, --help            show this help message and exit
  --xml                 Export as XML for Panorama
  --dg DEVICE_GROUP, --device-group DEVICE_GROUP
                        Panorama device group name
  --no-tags             Disable adding tags and descriptions to output rules
  --tag-name TAG_NAME   Custom tag name to apply to rules
  
We can get the converted rule set in Palo "SET" or "XML" commands

use --xml for XML file or Do not add the XML flag for SET CLI commands

Example of CLI SET command version: 
(by default this will include tags and comments, if you want to change it use --no-tags)

$ python3 asa_to_palo_converter.py asa_rules.txt palo_output.txt

palo_output.txt (filename can be any name)

set address "WEB_SERVERS_1" ip-netmask 192.168.3.1
set address "WEB_SERVERS_2" ip-netmask 192.168.3.2
set address-group WEB_SERVERS static [ "WEB_SERVERS_1" "WEB_SERVERS_2" ]

set rulebase security rules INSIDE_TO_OUTSIDE_1 from INSIDE
set rulebase security rules INSIDE_TO_OUTSIDE_1 to OUTSIDE
set rulebase security rules INSIDE_TO_OUTSIDE_1 source any
set rulebase security rules INSIDE_TO_OUTSIDE_1 destination WEB_SERVERS
set rulebase security rules INSIDE_TO_OUTSIDE_1 service tcp-80
set rulebase security rules INSIDE_TO_OUTSIDE_1 action allow
set rulebase security rules INSIDE_TO_OUTSIDE_1 source-user any
set rulebase security rules INSIDE_TO_OUTSIDE_1 disabled no
set rulebase security rules INSIDE_TO_OUTSIDE_1 log-start no
set rulebase security rules INSIDE_TO_OUTSIDE_1 log-end yes
set rulebase security rules INSIDE_TO_OUTSIDE_1 description "Converted from ASA rule: INSIDE_TO_OUTSIDE_1"
set rulebase security rules INSIDE_TO_OUTSIDE_1 tag from-asa

set rulebase security rules OUTSIDE_TO_INSIDE_2 from OUTSIDE
set rulebase security rules OUTSIDE_TO_INSIDE_2 to INSIDE
set rulebase security rules OUTSIDE_TO_INSIDE_2 source any
set rulebase security rules OUTSIDE_TO_INSIDE_2 destination 200.16.0.0/24
set rulebase security rules OUTSIDE_TO_INSIDE_2 service tcp-443
set rulebase security rules OUTSIDE_TO_INSIDE_2 action allow
set rulebase security rules OUTSIDE_TO_INSIDE_2 source-user any
set rulebase security rules OUTSIDE_TO_INSIDE_2 disabled no
set rulebase security rules OUTSIDE_TO_INSIDE_2 log-start no
set rulebase security rules OUTSIDE_TO_INSIDE_2 log-end yes
set rulebase security rules OUTSIDE_TO_INSIDE_2 description "Converted from ASA rule: OUTSIDE_TO_INSIDE_2"
set rulebase security rules OUTSIDE_TO_INSIDE_2 tag from-asa

set rulebase security rules INSIDE_TO_OUTSIDE_3 from INSIDE
set rulebase security rules INSIDE_TO_OUTSIDE_3 to OUTSIDE
set rulebase security rules INSIDE_TO_OUTSIDE_3 source any
set rulebase security rules INSIDE_TO_OUTSIDE_3 destination any
set rulebase security rules INSIDE_TO_OUTSIDE_3 service any
set rulebase security rules INSIDE_TO_OUTSIDE_3 action allow
set rulebase security rules INSIDE_TO_OUTSIDE_3 source-user any
set rulebase security rules INSIDE_TO_OUTSIDE_3 disabled no
set rulebase security rules INSIDE_TO_OUTSIDE_3 log-start no
set rulebase security rules INSIDE_TO_OUTSIDE_3 log-end yes
set rulebase security rules INSIDE_TO_OUTSIDE_3 description "Converted from ASA rule: INSIDE_TO_OUTSIDE_3"
set rulebase security rules INSIDE_TO_OUTSIDE_3 tag from-asa

Example of XML version: 
(This will create a Panorama friendly version that can use a device-group name by adding the --dg flag)

$ python3 asa_to_palo_converter.py asa_rules.txt palo_output.xml --xml --dg "Branch1"

palo_output.xml (filename can be any name)

<?xml version='1.0' encoding='utf-8'?>
<config>
    <devices>
        <entry name="localhost.localdomain">
            <shared>
                <address>
                    <entry name="WEB_SERVERS_1">
                        <ip-netmask>192.168.3.1</ip-netmask>
                    </entry>
                    <entry name="WEB_SERVERS_2">
                        <ip-netmask>192.168.3.2</ip-netmask>
                    </entry>
                </address>
                <address-group>
                    <entry name="WEB_SERVERS">
                        <static>
                            <member>WEB_SERVERS_1</member>
                            <member>WEB_SERVERS_2</member>
                        </static>
                    </entry>
                </address-group>
            </shared>
            <device-group>
                <entry name="Branch1">
                    <pre-rulebase>
                        <security>
                            <rules>
                                <entry name="INSIDE_TO_OUTSIDE_1">
                                    <from>
                                        <member>INSIDE</member>
                                    </from>
                                    <to>
                                        <member>OUTSIDE</member>
                                    </to>
                                    <source>
                                        <member>any</member>
                                    </source>
                                    <destination>
                                        <member>WEB_SERVERS</member>
                                    </destination>
                                    <service>
                                        <member>tcp-80</member>
                                    </service>
                                    <action>allow</action>
                                    <source-user>
                                        <member>any</member>
                                    </source-user>
                                    <log-end>yes</log-end>
                                    <description>Converted from ASA rule: INSIDE_TO_OUTSIDE_1</description>
                                    <tag>
                                        <member>from-asa</member>
                                    </tag>
                                </entry>
                                <entry name="OUTSIDE_TO_INSIDE_2">
                                    <from>
                                        <member>OUTSIDE</member>
                                    </from>
                                    <to>
                                        <member>INSIDE</member>
                                    </to>
                                    <source>
                                        <member>any</member>
                                    </source>
                                    <destination>
                                        <member>200.16.0.0/24</member>
                                    </destination>
                                    <service>
                                        <member>tcp-443</member>
                                    </service>
                                    <action>allow</action>
                                    <source-user>
                                        <member>any</member>
                                    </source-user>
                                    <log-end>yes</log-end>
                                    <description>Converted from ASA rule: OUTSIDE_TO_INSIDE_2</description>
                                    <tag>
                                        <member>from-asa</member>
                                    </tag>
                                </entry>
                                <entry name="INSIDE_TO_OUTSIDE_3">
                                    <from>
                                        <member>INSIDE</member>
                                    </from>
                                    <to>
                                        <member>OUTSIDE</member>
                                    </to>
                                    <source>
                                        <member>any</member>
                                    </source>
                                    <destination>
                                        <member>any</member>
                                    </destination>
                                    <service>
                                        <member>any</member>
                                    </service>
                                    <action>allow</action>
                                    <source-user>
                                        <member>any</member>
                                    </source-user>
                                    <log-end>yes</log-end>
                                    <description>Converted from ASA rule: INSIDE_TO_OUTSIDE_3</description>
                                    <tag>
                                        <member>from-asa</member>
                                    </tag>
                                </entry>
                            </rules>
                        </security>
                    </pre-rulebase>
                </entry>
            </device-group>
        </entry>
    </devices>
</config>

"End of Version 3 Demo"
## 🤝 Contributing
