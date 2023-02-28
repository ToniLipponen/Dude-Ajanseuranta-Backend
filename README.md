# Building

This project uses cmake as the build system. Below are the steps required to make this build.

## Dependencies
- Httplib
- OpenSSL3
- MariaDB
- MariaDB Connector/C++
- 🍔
- Compiler that supports C++17


Building in debug mode
``` 
cmake -B build
cmake --build build --parallel
```

Building in release mode
```
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Running
``` 
./build/app 
```

## TODO
- [ ] Lock mutex when using sql::Connection
- [ ] Refactor everything
- [ ] Split code into smaller files
- [ ] Write documentation
- [ ] sql::Properties in Config.h
- [ ] In Application::AddAdmin() make sure admin with a given name doesn't already exist