# Examples
# Poor man's test

HOST=aldea

function header {
	echo -e '>==============================================================================='
	echo -e "> $1"
	echo -e "<enter to continue>"
	echo -e '>==============================================================================='
	read
}

header 'remove all blacklist and whitelist usages (whitelist call forced)'
./ip_list.py -n $HOST -r -m "." -i "." -b
./ip_list.py -n $HOST -r -m "." -i "." -w -f

header 'remove all log-only flags (whitelist call forced)'
./ip_list.py -n $HOST -o disable -m "." -b -f
./ip_list.py -n $HOST -o disable -m "." -w

header 'add IP List "aaa" to blacklist of host "aldea" on all mapping containing the string "basic"'
./ip_list.py -n $HOST -a -m "basic" -i "^aaa" -b

header 'show all blacklist and whitelist usages'
./ip_list.py -n $HOST -s -m "." -b
./ip_list.py -n $HOST -s -m "." -w

header 'add IP list starting with letter 'a' to all mappings containing string "s"'
./ip_list.py -n $HOST -a -m "s" -i "^a" -b

header 'enable log-only on whitelist for all mappings with a label test99'
./ip_list.py -n $HOST -o enable -l "test99" -w

header 'show all blacklist and whitelist usages'
./ip_list.py -n $HOST -s -m "." -b
./ip_list.py -n $HOST -s -m "." -w

header 'error mapping not found - with label '
./ip_list.py -n $HOST -o enable -l "foo" -w

header 'error mapping not found - with mapping pattern'
./ip_list.py -n $HOST -r -m "foo" -w -i "."

header 'error ip list not found '
./ip_list.py -n $HOST -a -m "." -i "foo" -w
