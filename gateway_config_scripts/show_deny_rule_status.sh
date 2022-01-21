#!/bin/bash

# Version 1.1
# Queries Airlock Gateway Config XML/ZIP for Deny Rule status
# Tested with Airlock Gateway 7.7

OPTIND=1

file=""
rule=""
enabled="true"

function usage()
{
	cat <<EOF
Usage: $0 -f <config_zip_file> -r <RULE_SHORTNAME> [-d]
		-f: Airlock Gateway config zip
		-r: Deny Rule short name (e.g. SQL_001a)
		-d: show mappings where rule is not active
EOF
}


while getopts ":f:r:d" opt; do
	case "${opt}" in
		f)  file=${OPTARG}
			;;
		r)  rule=${OPTARG}
			;;
		d)  enabled="false"
			;;
		*)  usage
			exit 1
			;;
	esac
done

if [ -z "${file}" ] || [ -z "${rule}" ]; then
	usage
	exit 1
fi

tmp=$(mktemp -d)
trap "rm -rf ${tmp}" EXIT

unzip "${file}" -d $tmp/ > /dev/null
cat $tmp/alec_full.xml | tr -d " \n\r\t" > $tmp/alec_no_spaces.xml

# Assumption 1: all rule names start with `default`
# Pattern 1 finds the ID corresponding to the rule name given as argument to this script.
pattern1="(?<=<DenyRuleId=\")-\d+(?=\"><Name>\(default${rule}\))"
deny_rule_id=$(cat ${tmp}/alec_no_spaces.xml | grep -Po "${pattern1}")
echo "Found Deny Rule ID: ${deny_rule_id}"

# Pattern 2 is used to extract the xml part defining the wanted rule
pattern2="<DenyRuleId=\"${deny_rule_id}\">.*?</DenyRule>" 
# Assumption 2: No rule is contained in more than 1 Deny Rule Group.
# Pattern 3 extracts the first Deny Rule Group ID in which the rule is contained 
pattern3="(?<=<DenyRuleGroupIds><DenyRuleGroupId>)-\d+(?=</DenyRuleGroupId>)"
deny_rule_group_id=$(cat ${tmp}/alec_no_spaces.xml | grep -Po ${pattern2} | grep -Po "${pattern3}")
echo "Found Deny Rule Group ID: ${deny_rule_group_id}"

# Pattern 4 is used to extract 3 things for every mapping: its name, whether the Deny Rule Group is enabled or not and whether the Deny Rule itself is enabled or not. 
pattern4="<MappingId=\"(\d+)\".*?<Name>.*?</Name(*SKIP)>|<DenyRuleGroupId>${deny_rule_group_id}</DenyRuleGroupId><EnabledLocked=\"(?:false|true)\">true<\/Enabled>|<DenyRuleId>${deny_rule_id}</DenyRuleId><Enabled.*?>(*SKIP)true<\/Enabled>"
# Pattern 5 checks if a mapping has both the Deny Rule Group as well as the Deny Rule enabled, and outputs its name if that is the case
pattern5="(?<=<Name>).*?(?=</Name(*SKIP)><DenyRuleGroupId>${deny_rule_group_id}</DenyRuleGroupId><EnabledLocked=\"(?:false|true)\">true</Enabled><DenyRuleId>)"

active_mappings=$(grep -Po "${pattern4}" ${tmp}/alec_no_spaces.xml | tr -d " \n\r\t" | grep -Po "${pattern5}")

if [ $enabled = "true" ]
then
	echo 
	echo "Mappings with Deny Rule ${rule} active: "
	echo "$active_mappings"
else
	# Pattern 6 in combination with pattern 7 extracts all mapping names
	pattern6="<MappingId=\"(\d+)\".*?<Name>.*?</Name(*SKIP)>"
	pattern7="(?<=<Name>).*?(?=</Name>)"
	# Pattern 8 matches all mapping names where the rule is active.
	pattern8=$(echo "${active_mappings}" | sed -z 's/\n/|/g;s/|$/\n/')
	# The last grep is inverted (-v flag) so that only the mapping names where the rule is NOT active will be matched
	not_active_mappings=$(grep -Po "${pattern6}" ${tmp}/alec_no_spaces.xml | tr -d " \n\r\t" | grep -Po "${pattern7}" | grep -Pv "${pattern8}")
	echo
	echo "Mappings with Deny Rule ${rule} not active: "
	echo "$not_active_mappings"
fi
