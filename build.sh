rm -rf ./build/*

conan install . --output-folder=build --build=missing

cd build

cmake ..  \
    -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake \
    -DProtobuf_PROTOC_EXECUTABLE=~/.conan2/p/b/proto6d1ad163e756e/p/bin/protoc \
    -DCMAKE_BUILD_TYPE=Release

make -j2