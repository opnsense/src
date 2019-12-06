#!/usr/bin/env sh

fail()
{
	echo $*
	exit 1
}

BASEDIR=`pwd`
BASEDIR="${BASEDIR%/hbsdcontrol}"
test -d "hbsdcontrol" || fail "missing hbsdcontrol directory"

TMPDIR="`mktemp -d`/hbsdcontrol"

echo "Cloning the lastest version to ${TMPDIR}"
git clone 'https://github.com/opntr/hbsdcontrol' "${TMPDIR}"

cd "${TMPDIR}"
test -d "contrib/hardenedbsd/" || fail "missing contrib/hardenedbsd directory"
GIT_REVISION="`git rev-parse HEAD`"

cd "${TMPDIR}/contrib/hardenedbsd/"
tar cf - hbsdcontrol | (cd "${BASEDIR}"; tar xvf -)
cd "${BASEDIR}"
echo "${GIT_REVISION}" > hbsdcontrol/git_revision

git add hbsdcontrol
git commit -s -m "HBSD: import upstream version ${GIT_REVISION} of hbsdcontrol"

rm -r "${TMPDIR}"
