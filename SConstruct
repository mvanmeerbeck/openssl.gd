#!/usr/bin/env python
import os
from glob import glob

env = SConscript("godot-cpp/SConstruct")

env.Append(CPPPATH=["src/"])
sources = Glob("src/*.cpp")

(addon_path,) = glob("addons/*/")

scons_cache_path = os.environ.get("SCONS_CACHE")
if scons_cache_path != None:
    CacheDir(scons_cache_path)
    print("Scons cache enabled... (path: '" + scons_cache_path + "')")

if env["platform"] == "osx":
    library = env.SharedLibrary(
        "{}/bin/libgdextension.{}.{}.framework/libgdextension.{}.{}".format(
            addon_path,
            env["platform"],
            env["target"],
            env["platform"],
            env["target"],
        ),
        source=sources,
    )
else:
    library = env.SharedLibrary(
        "{}/bin/libgdextension.{}.{}.{}{}".format(
            addon_path,
            env["platform"],
            env["target"],
            env["arch_suffix"],
            env["SHLIBSUFFIX"],
        ),
        source=sources,
    )

Default(library)
