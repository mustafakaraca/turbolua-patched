if ngx then
  return {
    md5 = ngx.md5
  }
end
local ok, hash = pcall(require, "turbo.hash")
if ok and hash then
  return {
    md5 = function(str)
      local h = hash.MD5(str)
      h:finalize()
      return h:hex()
    end
  }
end
local crypto = require("crypto")
local md5
md5 = function(str)
  return crypto.digest("md5", str)
end
return {
  md5 = md5
}
