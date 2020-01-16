var searchIndex={};
searchIndex["tokio_libssh2"] = {"doc":"libssh2 bindings library, focuses on the interoperability…","i":[[3,"Channel","tokio_libssh2","A portion of an SSH connection on which data can be read…",null,null],[3,"Stream","","The stream associated with a `Channel`.",null,null],[3,"Error","","",null,null],[3,"Session","","A handle to an SSH session.",null,null],[0,"auth","","Authentication of a session.",null,null],[3,"AuthContext","tokio_libssh2::auth","",null,null],[3,"PasswordAuth","","An `Authenticator` using the password.",null,null],[5,"password","","Create a `PasswordAuth` with the provided password string.",null,[[["str"],["asref",["str"]]],[["str"],["passwordauth"],["asref",["str"]]]]],[8,"Authenticator","","",null,null],[10,"poll_authenticate","","",0,[[["context"],["pin"],["authcontext"],["self"]],[["poll",["result"]],["result"]]]],[11,"setenv","tokio_libssh2","Set an environment variable in the remote channel's…",1,[[["self"],["str"]]]],[11,"process_startup","","Initiate a request on a session type channel.",1,[[["self"],["str"],["option",["str"]]]]],[11,"shell","","Start a shell.",1,[[["self"]]]],[11,"exec","","Execute a command.",1,[[["self"],["str"]]]],[11,"subsystem","","Request a subsystem be started.",1,[[["self"],["str"]]]],[11,"stream","","Return a handle to a particular stream for this channel.",1,[[["self"],["i32"]],["stream"]]],[11,"exit_status","","",1,[[["self"]],[["i32"],["result",["i32"]]]]],[11,"close","","",1,[[["self"]]]],[11,"new","","Initialize an SSH session.",2,[[],["result"]]],[11,"set_banner","","Set the banner that will be sent to the remote host when…",2,[[["self"]],["result"]]],[11,"handshake","","Start the transport layer protocol negotiation with the…",2,[[["tcpstream"],["self"]]]],[11,"authenticate","","Attempt the specified authentication.",2,[[["a"],["self"],["str"]]]],[11,"authenticated","","Return whether the session has been successfully…",2,[[["self"]],["bool"]]],[11,"list_userauth","","List the supported authentication methods for an user.",2,[[["str"],["self"]]]],[11,"open_channel","","",2,[[["option",["str"]],["u32"],["self"],["str"],["option",["u32"]]]]],[11,"open_channel_session","","",2,[[["self"]]]],[11,"sftp","","",2,[[["self"]]]],[0,"sftp","","SFTP subsystem.",null,null],[3,"FileAttr","tokio_libssh2::sftp","The metadata about a remote file.",null,null],[3,"DirEntry","","",null,null],[3,"OpenOptions","","",null,null],[3,"Sftp","","A handle to a remote filesystem over SFTP.",null,null],[3,"File","","A file handle corresponding to an SFTP connection.",null,null],[3,"Dir","","A directory handle corresponding to an SFTP connection.",null,null],[11,"permissions","","Return the permission flags of the file, if specified.",3,[[["self"]],[["option",["u64"]],["u64"]]]],[11,"filesize","","Return the file size of the file in bytes, if specified.",3,[[["self"]],[["option",["u64"]],["u64"]]]],[11,"uid","","Return the user ID of the file owner, if specified.",3,[[["self"]],[["u32"],["option",["u32"]]]]],[11,"gid","","Returns the group ID of the file owner, if specified.",3,[[["self"]],[["u32"],["option",["u32"]]]]],[11,"atime","","Return the last access time of the file in seconds, if…",3,[[["self"]],[["option",["u64"]],["u64"]]]],[11,"mtime","","Return the last modified time of the file in seconds, if…",3,[[["self"]],[["option",["u64"]],["u64"]]]],[11,"new","","",4,[[],["self"]]],[11,"read","","",4,[[["self"],["bool"]],["self"]]],[11,"write","","",4,[[["self"],["bool"]],["self"]]],[11,"append","","",4,[[["self"],["bool"]],["self"]]],[11,"create","","",4,[[["self"],["bool"]],["self"]]],[11,"truncate","","",4,[[["self"],["bool"]],["self"]]],[11,"exclusive","","",4,[[["self"],["bool"]],["self"]]],[11,"mode","","",4,[[["self"],["i32"]],["self"]]],[11,"open","","",4,[[["sftp"],["self"],["p"]]]],[11,"stat","","Acquire the metadata for a file.",5,[[["self"]]]],[11,"lstat","","Acquire the metadata for a file.",5,[[["self"]]]],[11,"setstat","","",5,[[["fileattr"],["self"]]]],[11,"open","","",5,[[["self"]]]],[11,"opendir","","",5,[[["self"]]]],[11,"stat","","",6,[[["self"]]]],[11,"setstat","","",6,[[["fileattr"],["self"]]]],[11,"read","","",6,[[["self"]]]],[11,"write","","",6,[[["self"]]]],[11,"fsync","","Synchronize the file data and metada to the disk on the…",6,[[["self"]]]],[11,"stat","","Acquire the attribute information of this directory.",7,[[["self"]]]],[11,"setstat","","Set the attribute information of the directory.",7,[[["fileattr"],["self"]]]],[11,"readdir","","Read an entry from the directory, if any.",7,[[["self"]]]],[6,"Result","tokio_libssh2","",null,null],[11,"from","","",1,[[["t"]],["t"]]],[11,"into","","",1,[[],["u"]]],[11,"try_from","","",1,[[["u"]],["result"]]],[11,"try_into","","",1,[[],["result"]]],[11,"borrow","","",1,[[["self"]],["t"]]],[11,"borrow_mut","","",1,[[["self"]],["t"]]],[11,"type_id","","",1,[[["self"]],["typeid"]]],[11,"from","","",8,[[["t"]],["t"]]],[11,"into","","",8,[[],["u"]]],[11,"try_from","","",8,[[["u"]],["result"]]],[11,"try_into","","",8,[[],["result"]]],[11,"borrow","","",8,[[["self"]],["t"]]],[11,"borrow_mut","","",8,[[["self"]],["t"]]],[11,"type_id","","",8,[[["self"]],["typeid"]]],[11,"from","","",9,[[["t"]],["t"]]],[11,"into","","",9,[[],["u"]]],[11,"to_string","","",9,[[["self"]],["string"]]],[11,"try_from","","",9,[[["u"]],["result"]]],[11,"try_into","","",9,[[],["result"]]],[11,"borrow","","",9,[[["self"]],["t"]]],[11,"borrow_mut","","",9,[[["self"]],["t"]]],[11,"type_id","","",9,[[["self"]],["typeid"]]],[11,"from","","",2,[[["t"]],["t"]]],[11,"into","","",2,[[],["u"]]],[11,"try_from","","",2,[[["u"]],["result"]]],[11,"try_into","","",2,[[],["result"]]],[11,"borrow","","",2,[[["self"]],["t"]]],[11,"borrow_mut","","",2,[[["self"]],["t"]]],[11,"type_id","","",2,[[["self"]],["typeid"]]],[11,"from","tokio_libssh2::auth","",10,[[["t"]],["t"]]],[11,"into","","",10,[[],["u"]]],[11,"try_from","","",10,[[["u"]],["result"]]],[11,"try_into","","",10,[[],["result"]]],[11,"borrow","","",10,[[["self"]],["t"]]],[11,"borrow_mut","","",10,[[["self"]],["t"]]],[11,"type_id","","",10,[[["self"]],["typeid"]]],[11,"from","","",11,[[["t"]],["t"]]],[11,"into","","",11,[[],["u"]]],[11,"try_from","","",11,[[["u"]],["result"]]],[11,"try_into","","",11,[[],["result"]]],[11,"borrow","","",11,[[["self"]],["t"]]],[11,"borrow_mut","","",11,[[["self"]],["t"]]],[11,"type_id","","",11,[[["self"]],["typeid"]]],[11,"from","tokio_libssh2::sftp","",3,[[["t"]],["t"]]],[11,"into","","",3,[[],["u"]]],[11,"try_from","","",3,[[["u"]],["result"]]],[11,"try_into","","",3,[[],["result"]]],[11,"borrow","","",3,[[["self"]],["t"]]],[11,"borrow_mut","","",3,[[["self"]],["t"]]],[11,"type_id","","",3,[[["self"]],["typeid"]]],[11,"from","","",12,[[["t"]],["t"]]],[11,"into","","",12,[[],["u"]]],[11,"try_from","","",12,[[["u"]],["result"]]],[11,"try_into","","",12,[[],["result"]]],[11,"borrow","","",12,[[["self"]],["t"]]],[11,"borrow_mut","","",12,[[["self"]],["t"]]],[11,"type_id","","",12,[[["self"]],["typeid"]]],[11,"from","","",4,[[["t"]],["t"]]],[11,"into","","",4,[[],["u"]]],[11,"try_from","","",4,[[["u"]],["result"]]],[11,"try_into","","",4,[[],["result"]]],[11,"borrow","","",4,[[["self"]],["t"]]],[11,"borrow_mut","","",4,[[["self"]],["t"]]],[11,"type_id","","",4,[[["self"]],["typeid"]]],[11,"from","","",5,[[["t"]],["t"]]],[11,"into","","",5,[[],["u"]]],[11,"try_from","","",5,[[["u"]],["result"]]],[11,"try_into","","",5,[[],["result"]]],[11,"borrow","","",5,[[["self"]],["t"]]],[11,"borrow_mut","","",5,[[["self"]],["t"]]],[11,"type_id","","",5,[[["self"]],["typeid"]]],[11,"from","","",6,[[["t"]],["t"]]],[11,"into","","",6,[[],["u"]]],[11,"try_from","","",6,[[["u"]],["result"]]],[11,"try_into","","",6,[[],["result"]]],[11,"borrow","","",6,[[["self"]],["t"]]],[11,"borrow_mut","","",6,[[["self"]],["t"]]],[11,"type_id","","",6,[[["self"]],["typeid"]]],[11,"from","","",7,[[["t"]],["t"]]],[11,"into","","",7,[[],["u"]]],[11,"try_from","","",7,[[["u"]],["result"]]],[11,"try_into","","",7,[[],["result"]]],[11,"borrow","","",7,[[["self"]],["t"]]],[11,"borrow_mut","","",7,[[["self"]],["t"]]],[11,"type_id","","",7,[[["self"]],["typeid"]]],[11,"poll_authenticate","tokio_libssh2::auth","",11,[[["context"],["pin"],["authcontext"],["self"]],[["poll",["result"]],["result"]]]],[11,"drop","tokio_libssh2","",1,[[["self"]]]],[11,"drop","","",2,[[["self"]]]],[11,"drop","tokio_libssh2::sftp","",5,[[["self"]]]],[11,"from","tokio_libssh2","",9,[[["error"]],["self"]]],[11,"from","","",9,[[["nulerror"]],["self"]]],[11,"default","tokio_libssh2::sftp","",4,[[],["openoptions"]]],[11,"fmt","tokio_libssh2","",9,[[["self"],["formatter"]],["result"]]],[11,"fmt","tokio_libssh2::sftp","",3,[[["self"],["formatter"]],["result"]]],[11,"fmt","","",12,[[["self"],["formatter"]],["result"]]],[11,"fmt","","",4,[[["self"],["formatter"]],["result"]]],[11,"fmt","tokio_libssh2","",9,[[["self"],["formatter"]],["result"]]],[11,"source","","",9,[[["self"]],[["option",["error"]],["error"]]]],[11,"poll_read","","",1,[[["context"],["pin"],["self"]],[["poll",["result"]],["result",["usize"]]]]],[11,"poll_read","","",8,[[["context"],["pin"],["self"]],[["poll",["result"]],["result",["usize"]]]]],[11,"poll_read","tokio_libssh2::sftp","",6,[[["context"],["pin"],["self"]],[["poll",["result"]],["result",["usize"]]]]],[11,"poll_write","tokio_libssh2","",1,[[["context"],["pin"],["self"]],[["poll",["result"]],["result",["usize"]]]]],[11,"poll_flush","","",1,[[["context"],["self"],["pin"]],[["result"],["poll",["result"]]]]],[11,"poll_shutdown","","",1,[[["context"],["self"],["pin"]],[["result"],["poll",["result"]]]]],[11,"poll_write","","",8,[[["context"],["pin"],["self"]],[["poll",["result"]],["result",["usize"]]]]],[11,"poll_flush","","",8,[[["context"],["self"],["pin"]],[["result"],["poll",["result"]]]]],[11,"poll_shutdown","","",8,[[["context"],["self"],["pin"]],[["result"],["poll",["result"]]]]],[11,"poll_write","tokio_libssh2::sftp","",6,[[["context"],["pin"],["self"]],[["poll",["result"]],["result",["usize"]]]]],[11,"poll_flush","","",6,[[["context"],["self"],["pin"]],[["result"],["poll",["result"]]]]],[11,"poll_shutdown","","",6,[[["context"],["self"],["pin"]],[["result"],["poll",["result"]]]]]],"p":[[8,"Authenticator"],[3,"Channel"],[3,"Session"],[3,"FileAttr"],[3,"OpenOptions"],[3,"Sftp"],[3,"File"],[3,"Dir"],[3,"Stream"],[3,"Error"],[3,"AuthContext"],[3,"PasswordAuth"],[3,"DirEntry"]]};
addSearchOptions(searchIndex);initSearch(searchIndex);