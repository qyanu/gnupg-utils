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
OPTPACKAGE="multiclearsign"
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
EX_SOFTWARE=70
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


# general purpose temporary files on disk
# automatically freed by OS upon exit
TEMPFILEPATH3="$(mktemp)"
exec 3<>"${TEMPFILEPATH3}"
rm -f "${TEMPFILEPATH3}"
TEMPFILEPATH3="/proc/self/fd/3"

TEMPFILEPATH4="$(mktemp)"
exec 4<>"${TEMPFILEPATH4}"
rm -f "${TEMPFILEPATH4}"
TEMPFILEPATH4="/proc/self/fd/4"

TEMPFILEPATH5="$(mktemp)"
exec 5<>"${TEMPFILEPATH5}"
rm -f "${TEMPFILEPATH5}"
TEMPFILEPATH5="/proc/self/fd/5"


##
## test if the first argument is equal to any of the other arguments
## using with an array like this:
##     StringEqualToAnyOf "$needle" "${haystack[@]}"
## the return value is $EX_YES if $needle is equal to any of the other strings,
## or $EX_NO otherwise.
##
## if there are zero haystack-strings (the empty set), $EX_NO is returned.
## if also needle is missing the result is undefined.
##
## Synopsis:
##     StringEqualToAnyOf NEEDLE [HAYSTACKELEMENT1] [HAYSTACKELEMENT2] ...
##
function StringEqualToAnyOf() {
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
    echoerr "Missing util: gpg2"
    exit $EX_OSFILE
}



#
# function that checks whether the file already contains a pgp signature block
#
# $1 ... the file to check
# return code ... EX_YES if there is a block present, EX_NO if not. other
#     codes if an error occurs
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
# swaps in the new file for the existing file
#
# $1 ... new file
# $2 ... old file, will be overwritten
# return code ... $EX_OK on success, or the appropriate error code
# stdout ... nothing
#
function swapNewFile() {
    local newfile="$1"
    local filepath="$2"
    echoerr "Replacing $filepath with new file"
    local thedir="$(dirname "$filepath")" || return
    local copy="$(mktemp -p "$thedir")" || return
    cat "$newfile" > "$copy" || return
    mv "$copy" "$filepath"
}



filepath="$1"
[[ -n "$filepath" ]] || {
    echoerr "Usage: $MYNAME [file]"
    exit "$EX_USAGE"
}


hasFileASignatureBlock "$filepath"
ex="$?"

# short path: no signature found, just do normal clearsign
[[ "$ex" -eq "$EX_NO" ]] && {
    "$GPG" --yes --clearsign --output "$TEMPFILEPATH3" "$filepath"
    swapNewFile "$TEMPFILEPATH3" "$filepath"
    echo -n > "$TEMPFILEPATH3"
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

StringEqualToAnyOf "$HASHALG" "MD5" "SHA1" "SHA256" "SHA512" || {
    echoerr "Warning: Using Hash Algo: $HASHALG"
}



# make a new signature of the document itself (without the existing signature)
"$GPG" --yes --output "$TEMPFILEPATH3" --decrypt "$filepath" 2>/dev/null
"$GPG" --yes --digest-algo "$HASHALG" --clearsign --output "$TEMPFILEPATH4" "$TEMPFILEPATH3"
echo -n > "$TEMPFILEPATH3"


# extract both signature packet from the respective openpgp blocks
sed -n '/^-----BEGIN PGP SIGNATURE-----$/,/^-----END PGP SIGNATURE-----$/ p' "$filepath" \
  | "$GPG" --dearmor \
  | "$GPGSPLIT" --no-split \
  > "$TEMPFILEPATH3"
sed -n '/^-----BEGIN PGP SIGNATURE-----$/,/^-----END PGP SIGNATURE-----$/ p' "$TEMPFILEPATH4" \
  | "$GPG" --dearmor \
  | "$GPGSPLIT" --no-split \
  > "$TEMPFILEPATH5"
echo -n > "$TEMPFILEPATH4"

cat "$TEMPFILEPATH3" "$TEMPFILEPATH5" \
  | "$GPG" --enarmor \
  | sed -n -e '/^-----BEGIN PGP ARMORED FILE-----$/,/^$/ d' -e 'p' \
  | sed -n -e '$ d' -e 'p' \
  > "$TEMPFILEPATH4"
echo -n > "$TEMPFILEPATH3"
echo -n > "$TEMPFILEPATH5"


(
    echo "-----BEGIN PGP SIGNED MESSAGE-----"
    echo "Hash: $HASHALG"
    echo
    "$GPG" --yes --decrypt "$filepath" 2>/dev/null
    echo '-----BEGIN PGP SIGNATURE-----'
    echo "Version: $OPTPACKAGE $OPTVERSION"
    echo
    cat "$TEMPFILEPATH4"
    echo '-----END PGP SIGNATURE-----'
) > "$TEMPFILEPATH3"

echoerr "The new files verifies as follows:"
"$GPG" --verify "$TEMPFILEPATH3"
ex="$?"
[[ "$ex" -eq 0 ]] || {
    echoerr "ERROR: the new file did not verify, keeping the original."
    exit "$EX_SOFTWARE"
}

echoerr "Saving new file into $filepath"
swapNewFile "$TEMPFILEPATH3" "$filepath"
