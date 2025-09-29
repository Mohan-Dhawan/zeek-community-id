# Zeek package & plugin for adding community hash IDs to conn.log.
# This is loaded when a user activates the plugin.
#
module CommunityID;

export {
    ## The Community ID hashing operation includes a seed value that can be
    ## used to reliably distinguish the resulting ID values of different sites.
    ## The default seed is zero.
    option seed: count = 0;

    ## By default, the Community ID includes a base64 encoding pass that
    ## shortens the output. For troubleshooting or performance tweaks it can
    ## prove handy to disable this pass.
    option do_base64: bool = T;

    # Verbose debugging log output to the console.
    option verbose: bool = F;

    # Add the ID string field to the connection log record.
    redef record Conn::Info += {
        community_id: string &optional &log;
    };
}

event connection_state_remove(c: connection) {
    c$conn$community_id = CommunityID::hash_conn(c);
}
