"use strict";

module.exports = {
  port: process.env.PORT,
  local_client_app: process.env.LOCAL_CLIENT_APP,
  remote_client_app: process.env.REMOTE_CLIENT_APP,
  local_server_api: process.env.LOCAL_SERVER_API,
  remote_server_api: process.env.REMOTE_SERVER_API,
  mongodb_connect: process.env.MONGODB_CONNECT,
  allowedDomains: process.env.NODE_ENV === 'production' ? [process.env.REMOTE_SERVER_API, process.env.REMOTE_CLIENT_APP] : [process.env.LOCAL_SERVER_API, process.env.LOCAL_CLIENT_APP]
};