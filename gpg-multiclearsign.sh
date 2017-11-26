#!/bin/bash

##
## This file has the purpose to add (another) clearsign signature to a,
## possibly already clearsigned, txt file.
##
## The original instructions are taken from:
## https://lists.gnupg.org/pipermail/gnupg-users/2013-July/047118.html
##
##
## Intended Function:
##
## Invoking gpg --clearsign multiple times will wrap the txt document as
## many times. Besides making the txt document harder to read it makes
## verification complicated and is generally ugly.
##
## As a solution, if the txt document is currently not clearsigned, it is
## clearsigned as if `gpg --clearsign` was used directly. But if a signature
## is already present, an additional OpenPGP signature packet is amended to
## the _existing pgp block_.
##
##


###############################################################################
################################## CHANGELOG ##################################
###############################################################################

# 2017-11-20 <max-julian@pogner.at>  corrections suggested by, and improvements
#     discussed with Andreas Hubert <andreas@hubert.digital> and
#     Christian Amsüss <chrysn@amsuess.com>
# 2017-11-07 <max-julian@pogner.at>  initial file creation



###############################################################################
########################### INIT AND SMALL HELPERS ############################
###############################################################################


## create files with restrictive umask by default, because
##   $ touch file
##   $ chmod og-rwx file
## would give the attacker an opportunity to open the file before access
## is restricted.
umask 077

##
## common and global variables
##
MYNAME="$0"
OPTPACKAGE="gpg-multiclearsign"
OPTVERSION="0.1"
MYDIR="$(dirname "$0")"


##
## codes reserved by bash
##
EX_OK=0
EX_GENERAL_ERROR=1
EX_MISUSE_OF_BUILTIN=2
# gap from 3 to 125
EX_COMMAND_CANNOT_EXEC=126
EX_COMMAND_NOT_FOUND=127
EX_INVALID=128
EX_SIGNAL_1=129
EX_SIGNAL_2=130
EX_SIGNAL_INT=130
EX_SIGNAL_9=137
EX_SIGNAL_KILL=137
EX_SIGNAL_15=143
EX_SIGNAL_TERM=143
# gap from 166 to 254
EX_OUT_OF_RANGE=255


## codes from sysexits.h
##
EX_OK=0
# gap from 1 to 63
EX_BASE=64
EX_USAGE=64
EX_DATAERR=65
EX_NOINPUT=66
EX_NOUSER=67
EX_NOHOST=68
EX_UNAVAILABLE=69
EX_SOFTWARE=70     # internal software error
EX_OSERR=71
EX_OSFILE=72
EX_CANTCREAT=73
EX_IOERR=74
EX_TEMPFAIL=75
EX_PROTOCOL=76
EX_NOPERM=77
EX_CONFIG=78
# gap from 78 to 255


##
## my custom exit codes
##
EX_OK=0
EX_FAIL=1
# use range 16 to 32 for custom errors:
EX_YES=0
EX_NO=16



function echoerr() {
    echo "$@" >&2
}


## temporary files on disk
## automatically freed by OS upon exit

# the unwrapped message
TEMPMESSAGE="$(mktemp)"
exec 3<>"${TEMPMESSAGE}"
rm -f "${TEMPMESSAGE}"
TEMPMESSAGE="/proc/self/fd/3"

# the newly produced second clearsigned file (wrapped message + pgp blocks)
TEMPSECONDSIGNED="$(mktemp)"
exec 4<>"${TEMPSECONDSIGNED}"
rm -f "${TEMPSECONDSIGNED}"
TEMPSECONDSIGNED="/proc/self/fd/4"

# the existing signature packet(s), dearmored
TEMPSIGNPACKET1="$(mktemp)"
exec 5<>"${TEMPSIGNPACKET1}"
rm -f "${TEMPSIGNPACKET1}"
TEMPSIGNPACKET1="/proc/self/fd/5"

# the new signature packet, dearmored
TEMPSIGNPACKET2="$(mktemp)"
exec 6<>"${TEMPSIGNPACKET2}"
rm -f "${TEMPSIGNPACKET2}"
TEMPSIGNPACKET2="/proc/self/fd/6"

# the new wrapped message with pgp block (containing old and new packets)
TEMPNEWFILE="$(mktemp)"
exec 7<>"${TEMPNEWFILE}"
rm -f "${TEMPNEWFILE}"
TEMPNEWFILE="/proc/self/fd/7"


##
## test if the first argument is equal to any of the other arguments
## using with an array like this:
##     stringIsEqualToAnyOf "$needle" "${haystack[@]}"
## the return value is $EX_YES if $needle is equal to any of the other strings,
## or $EX_NO otherwise.
##
## if there are zero haystack-strings (the empty set), $EX_NO is returned.
## if also needle is missing the result is undefined.
##
## Synopsis:
##     stringIsEqualToAnyOf NEEDLE [HAYSTACKELEMENT1] [HAYSTACKELEMENT2] ...
##
function stringIsEqualToAnyOf() {
    [[ "$#" -eq 0 ]] && {
        # no needle given
        echoerr "misuse of ${FUNCNAME[0]}: NEEDLE mssing."
        return $EX_MISUSE_OF_BUILTIN
    }
    [[ "$#" -eq 1 ]] && {
        # needle is never part of the empty set
        return $EX_NO
    }
    local e
    for e in "${@:2}"; do
        [[ "$e" == "$1" ]] && {
            return $EX_YES
        }
    done
    return $EX_NO
}



###############################################################################
################################ SCRIPT PROPER ################################
###############################################################################

GPG="$(which gpg2)" || {
    echoerr "Missing util: gpg2"
    exit $EX_OSFILE
}
GPGSPLIT="$(which gpgsplit)" || {
    echoerr "Missing util: gpgsplit"
    exit $EX_OSFILE
}



#
# function that checks whether the file already contains a pgp signature block
#
# $1 ... the file to check
# return code ... EX_YES if there is a block present, EX_NO if not. other
#     codes if an error occurs
# stdout ... nothing
#
function hasFileASignatureBlock() {
    local filepath="$1"
    [[ -r "$filepath" ]] || return $EX_NOINPUT
    "$GPG" --verify "$filepath" >/dev/null 2>&1
    local ex="$?"
    [[ "$ex" -eq 0 ]] && return $EX_YES
    [[ "$ex" -eq 2 ]] && return $EX_NO
    return $EX_SOFTWARE
}

#
# either prints the result to stdout, or
# swaps in the new file for the existing file
#
# $1 ... file containing the result
# $2 ... 0 if stdout or 1 if replace should be performed
# $3 ... the argument filename, if replace
# return code ... $EX_OK on success, or the appropriate error code
# stdout ... result will be printed, or nothing
#
function outputResult() {
    local resultfile="$1"
    local doreplace="$2"
    local filepath="$2"
    if [[ "${doreplace}" -eq 0 ]]; then
        echoerr "writing result to stdout"
        cat "$resultfile"
    elif [[ "${doreplace}" -eq 1 ]]; then
        echoerr "Replacing $filepath with new file"
        local thedir="$(dirname "$filepath")" || return
        local copy="$(mktemp -p "$thedir")" || return
        cat "$resultfile" > "$copy" || return
        mv "$copy" "$filepath"
    else
        echoerr "Error: internal error in outputResult"
        exit "$EX_SOFTWARE"
    fi
}


##
## default command line options
##
PARM_DOREPLACE=0
PARM_FILE_ISSET=0
PARM_FILE_VALUE=""


##
## help output
##
## stderr: the help
##
function printhelp() {
    echoerr "NAME"
    echoerr "    $OPTPACKAGE -- clearsign a file with multiple signatures"
    echoerr ""
    echoerr "SYNOPSIS"
    echoerr "    ${MYNAME} [OPTIONS] [--] <FILE>"
    echoerr ""
    echoerr "SUMMARY"
    echoerr ""
    echoerr "  mimics \`gpg2 --clearsign <FILE>\`, but enables additional signatures"
    echoerr "to be added not just one."
    echoerr "By default, the signed result data is written to stdout."
    echoerr ""
    echoerr "  Note: The actual signing is done by \`gpg2\`."
    echoerr ""
    echoerr ""
    echoerr "DEPENDENCIES:"
    echoerr ""
    echoerr "  bash4, gpg2, gpgsplit, sed, coreutils"
    echoerr ""
    echoerr ""
    echoerr "OPTIONS:"
    echoerr ""
    echoerr "  -h --help  show this help and exit"
    echoerr ""
    echoerr "  --replace  instead of writing to stdout, FILE is replaced with the result"
    echoerr "      (using a temporary file and rename(2) )"
    echoerr ""
    echoerr "  --  all following arguments are non-options"
    echoerr ""
    echoerr ""
    echoerr "FILE:"
    echoerr ""
    echoerr "  The path to the file to be signed."
    echoerr ""
    echoerr ""
    echoerr "SECURITY CONSIDERATIONS:"
    echoerr ""
    echoerr "  In absence of software-bugs, the security guarantees of gpg2 --clearsign"
    echoerr "upheld."
    echoerr ""
    return $EX_OK
}


##
## parse the given parameters as commandline
##
## parameters: the command line
## effects: sets the global user-configureable variables
##
function parse_cmdline() {
    [[ "$#" -eq 0 ]] && {
        # print "error message" if no parameters given
        echoerr "Error: parameters required"
        printhelp
        return $EX_USAGE
    }

    while [[ "$#" -gt 0 ]]
    do
        local key="$1"

        case "$key" in

            --help)
                printhelp
                return $EX_USAGE
                ;;

            --replace)
                PARM_DOREPLACE="1"
                ;;

            # end of options
            --)
                break
                ;;

            # unknown options
            --*)
                logerror "unknown option: $key"
                return $EX_USAGE
                ;;

            ## non-option is FILE
            *)
                # only one file supported atm
                [[ "${PARM_FILE_ISSET}" -eq 0 ]] || {
                    echoerr "Error: only one FILE supported"
                    printhelp
                    return $EX_USAGE
                }
                PARM_FILE_ISSET=1
                PARM_FILE_VALUE="$key"
                ;;
        esac
        shift
    done

    # if arguments are still left, they are non-options
    [[ "$#" -gt 0 ]] && {
        # TODO: this block is duplicate code from inside the switch above and
        # should be undeuplicated sometime
        local key="$1"
        # only one file supported atm
        [[ "${PARM_FILE_ISSET}" -eq 0 ]] || {
            echoerr "Error: only one FILE supported"
            printhelp
            return $EX_USAGE
        }
        PARM_FILE_ISSET=1
        PARM_FILE_VALUE="$key"
    }

    # if no file given, display help
    [[ "${PARM_FILE_ISSET}" -eq 0 ]] && {
        echoerr "Error: missing FILE argument"
        printhelp
        return $EX_USAGE
    }

    return $EX_OK
}



parse_cmdline "$@"

filepath="$PARM_FILE_VALUE"
[[ -n "$filepath" ]] || {
    echoerr "Usage: $MYNAME [file]"
    exit "$EX_USAGE"
}


hasFileASignatureBlock "$filepath"
ex="$?"

# short path: no signature found, just do normal clearsign
[[ "$ex" -eq "$EX_NO" ]] && {
    "$GPG" --yes --clearsign --output "$TEMPNEWFILE" "$filepath"
    outputResult "$TEMPNEWFILE" "$PARM_DOREPLACE" "$PARM_FILE_VALUE"
    exit "$?"
}
# some error occured
[[ "$ex" -ne "$EX_YES" ]] && {
    exit "$ex"
}
# else: continue to amend second signature


# determine the message digest used by the existing signature by
# inspecting the Armor Headers and looking for the "Hash" header
HASHALG=$(
  sed -n '/^-----BEGIN PGP SIGNED MESSAGE-----$/,/^$/ p' "$filepath" \
    | sed -n '/^Hash: / p' - \
    | sed -re 's/^Hash: +(.*)$/\1/'
)

[[ -z "$HASHALG" ]] && {
    # default is MD5
    HASHALG="MD5"
}

stringIsEqualToAnyOf "$HASHALG" "MD5" "SHA1" "SHA256" "SHA512" || {
    echoerr "Warning: Using unknown hash algo: $HASHALG"
}



# make a new signature of the document itself (without the existing signature)
"$GPG" --yes --output "$TEMPMESSAGE" --decrypt "$filepath" 2>/dev/null
"$GPG" --yes --digest-algo "$HASHALG" --clearsign --output "$TEMPSECONDSIGNED" "$TEMPMESSAGE"


# extract both signature packets from the respective openpgp blocks
sed -n '/^-----BEGIN PGP SIGNATURE-----$/,/^-----END PGP SIGNATURE-----$/ p' "$filepath" \
  | "$GPG" --dearmor \
  | "$GPGSPLIT" --no-split \
  > "$TEMPSIGNPACKET1"
sed -n '/^-----BEGIN PGP SIGNATURE-----$/,/^-----END PGP SIGNATURE-----$/ p' "$TEMPSECONDSIGNED" \
  | "$GPG" --dearmor \
  | "$GPGSPLIT" --no-split \
  > "$TEMPSIGNPACKET2"


(
    echo "-----BEGIN PGP SIGNED MESSAGE-----"
    echo "Hash: $HASHALG"
    echo
    cat "$TEMPMESSAGE"
    echo '-----BEGIN PGP SIGNATURE-----'
    echo "Version: $OPTPACKAGE $OPTVERSION"
    echo
    cat "$TEMPSIGNPACKET1" "$TEMPSIGNPACKET2" \
        | "$GPG" --enarmor \
        | sed -n -e '/^-----BEGIN PGP ARMORED FILE-----$/,/^$/ d' -e 'p' \
        | sed -n -e '$ d' -e 'p'
    echo '-----END PGP SIGNATURE-----'
) > "$TEMPNEWFILE"

echoerr "The new files verifies as follows:"
"$GPG" --verify "$TEMPNEWFILE"
ex="$?"
[[ "$ex" -eq 0 ]] || {
    echoerr "ERROR: the new file did not verify, keeping the original."
    exit "$EX_SOFTWARE"
}

outputResult "$TEMPNEWFILE" "$PARM_DOREPLACE" "$PARM_FILE_VALUE"
