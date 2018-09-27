--- Turbo.lua syscall Module
--
-- Copyright 2013 John Abrahamsen
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
-- modes

local ffi = require "ffi"
local util = require "turbo.util"
local libtffi = util.load_libtffi()

local function add_c_def(t, sym)
	t[sym] = libtffi.get_c_def(sym)
end

local flags = {}
add_c_def(flags, "O_DIRECTORY")
add_c_def(flags, "O_NOFOLLOW")
--add_c_def(flags, "O_DIRECT")
add_c_def(flags, "S_IFMT")
add_c_def(flags, "S_IFSOCK")
add_c_def(flags, "S_IFLNK")
add_c_def(flags, "S_IFREG")
add_c_def(flags, "S_IFBLK")
add_c_def(flags, "S_IFDIR")
add_c_def(flags, "S_IFCHR")
add_c_def(flags, "S_IFIFO")
add_c_def(flags, "S_ISUID")
add_c_def(flags, "S_ISGID")
add_c_def(flags, "S_ISVTX")
add_c_def(flags, "S_IRWXU")
add_c_def(flags, "S_IRUSR")
add_c_def(flags, "S_IWUSR")
add_c_def(flags, "S_IXUSR")
add_c_def(flags, "S_IRWXG")
add_c_def(flags, "S_IRGRP")
add_c_def(flags, "S_IWGRP")
add_c_def(flags, "S_IXGRP")
add_c_def(flags, "S_IRWXO")
add_c_def(flags, "S_IROTH")
add_c_def(flags, "S_IWOTH")
add_c_def(flags, "S_IXOTH")

return flags
