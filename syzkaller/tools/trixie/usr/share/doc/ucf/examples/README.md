Basic usage examples
====================

This directory contains basic examples of *ucf*(1) usage.

Automatic generation of the necessary fragments for common cases can also be
achieved with *dh_ucf*(1) from *debhelper*(7).

Further examples
================

Remove a ucf controlled conffile during package upgrade
---------------------------------------------------------

    conffile=<Destination>
    IFS=: read -r cf pkg exists modified <<EOF
    $(ucfq -w $conffile)
    EOF
    # Sanity checks
    [ "$cf" = "$conffile" ] || error_exit # Bad, should never happen
    [ "$pkg" = "$DPKG_MAINTSCRIPT_PACKAGE" ] || return # Not our conffile
    # Remove $conffile if it exists and is unmodified.
    if [ "$exists" = Yes ] && [ "$modified" = No ]; then
        rm $conffile
    fi
    # Purge from ucf state.
    ucf --purge $conffile && ucfr --purge $DPKG_MAINTSCRIPT_PACKAGE $conffile


Rename a ucf controlled conffile during package upgrade
-------------------------------------------------------

    conffile=<Old>
    new_conffile=<New>
    # Copy if it exists
    [ -f $conffile ] && cp $conffile $new_conffile
    # Register new
    ucf input.conf $new_conffile
    ucfr $DPKG_MAINTSCRIPT_PACKAGE $new_conffile
    # Removals
    if [ -f $conffile ]; then
        rm $conffile
    else
        # The old conffile had been deleted, so
        # do the same for the new one.
        rm $new_conffile
    fi
    # Purge from ucf state.
    ucf --purge $conffile && ucfr --purge $DPKG_MAINTSCRIPT_PACKAGE $conffile
