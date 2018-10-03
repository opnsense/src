#!/bin/sh

#
# hbsdcontrol PoC in shell
#
# this program should be rewritten in C in the future
#

LSEXTATTR="/usr/sbin/lsextattr"
RMEXTATTR="/usr/sbin/rmextattr"
GETEXTATTR="/usr/sbin/getextattr"
SETEXTATTR="/usr/sbin/setextattr"
SYSCTL="/sbin/sysctl"

err()
{
	echo $*
	exit 1
}

usage()
{
	echo "$0: <class> <feature> <state> file"
	echo "	<class> := (boot|global|system|user)"
}

usage_wo_file()
{
	echo "$0: <class> <feature> <state>"
	echo "	<class> := (boot|global|system|user)"
}

usage_boot_system()
{
	err "not implemented - missing hbsdcontrol.sh support"
}


usage_class_global()
{
	usage_wo_file
	echo "	<feature> := (aslr|pageexec|mprotect|segvguard|disallow_map32bit)"
}

usage_class_fsea()
{
	usage
	echo "	<feature> := (aslr|pageexec|mprotect|segvguard|disallow_map32bit|shlibrandom)"
}

usage_state()
{
	echo "	<state> := (disable|opt-in|opt-out|enable|status)"
}

usage_state_simple()
{
	echo "	<state> := (disable|enable|status)"
}

usage_class_global_state()
{
	usage_class_global
	usage_state
}

usage_class_fsea_state()
{
	usage_class_fsea
	usage_state_simple
}


################################################################

class_boot()
{
	feature=$1
	shift
	case ${feature} in
		*)
			usage_boot_system $*
			;;
	esac
}

class_global_state_sysctl()
{
	feature=$1
	shift
	state=$1
	shift

	if [ ${state} = -1 ]
	then
		${SYSCTL} hardening.pax.${feature}.status
	else
		${SYSCTL} hardening.pax.${feature}.status=${state}
	fi	
}

class_global_state()
{
	feature=$1
	state=$2
	
	case ${state} in
		disable)
			state=0
			;;
		opt-in)
			state=1
			;;
		opt-out)
			state=2
			;;
		enable)
			state=3
			;;
		status)
			state=-1
			;;
		*)
			usage_class_global_state
			exit 1
			;;
	esac

	class_global_state_sysctl ${feature} ${state}
}

class_global()
{
	feature=$1
	shift

	case ${feature} in
		aslr)
			;&
		pageexec)
			;&
		mprotect)
			;&
		segvguard)
			;&
		disallow_map32bit)
			class_global_state ${feature} $*
			;;
		*)
			usage_class_global
			exit 1
			;;
	esac
}

class_system_state_extattr()
{
	namespace=$1
	shift
	feature=$1
	shift
	state=$1
	shift
	file="${1}"
	shift

	if [ -z ${file} ]
	then
		usage_class_fsea_state ${namespace}
		exit 1
	fi
		
	if [ ! -f ${file} ]
	then
		usage_class_fsea_state ${namespace}
		err "${file} not exists!"
	fi

	if [ ${state} = -1 ]
	then
		${GETEXTATTR} ${namespace} hbsd.pax.${feature} ${file}
	else
		${RMEXTATTR} ${namespace} hbsd.pax.${feature} ${file} > /dev/null 2>&1
		${RMEXTATTR} ${namespace} hbsd.pax.no${feature} ${file} > /dev/null 2>&1
		case ${state} in
			0)
				${SETEXTATTR} ${namespace} hbsd.pax.no${feature} 1 ${file}
				${SETEXTATTR} ${namespace} hbsd.pax.${feature} 0 ${file}
				;;
			1)
				${SETEXTATTR} ${namespace} hbsd.pax.${feature} 1 ${file}
				${SETEXTATTR} ${namespace} hbsd.pax.no${feature} 0 ${file}
				;;
		esac
	fi	
}

class_fsea_state()
{
	namespace=$1
	shift
	feature=$1
	shift
	state=$1
	shift
	
	case ${state} in
		disable)
			state=0
			;;
		enable)
			state=1
			;;
		status)
			state=-1
			;;
		*)
			usage_class_fsea_state ${namespace}
			exit 1
			;;
	esac

	class_system_state_extattr ${namespace} ${feature} ${state} $*
}

class_fsea()
{
	namespace=$1
	shift
	feature=$1
	shift
	case ${feature} in
		aslr)
			;&
		pageexec)
			;&
		mprotect)
			;&
		segvguard)
			;&
		disallow_map32bit)
			;&
		shlibrandom)
			class_fsea_state ${namespace} ${feature} $*
			;;
		*)
			usage_class_fsea ${namespace}
			exit 1
			;;
	esac
}

class_system()
{
	class_fsea system $*
}

class_user()
{
	class_fsea user $*
}

class="$1"
shift
case ${class} in
	boot)
		class_boot $*
		;;
	global)
		class_global $*
		;;
	system)
		class_system $*
		;;
	user)
		echo "not implemented - missing kernel support"
		class_user $*
		;;
	*)
		usage
		exit 1
		;;
esac

