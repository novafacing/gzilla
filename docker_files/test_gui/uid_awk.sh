awk -F: 'END {print "uid:"u" gid:"g" groups:"gg}{if($1=="Uid"){split($2,a," ");u=a[1]}if($1=="Gid"){split($2,a," ");g=a[1]}if($1=="Groups"){gg=$2}}' /proc/self/status
