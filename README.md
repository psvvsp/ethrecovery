# ethrecovery
Ethereum wallets mnemonic recovery

# Build under Ubuntu (26.04)
1. sudo apt install cmake
2. sudo apt install nvidia-cuda-toolkit
3. sudo apt install -y gcc-13 g++-13
4. cd <project directory>
5. cmake -S . -B build -D CMAKE_BUILD_TYPE=Release -DCMAKE_CUDA_HOST_COMPILER=/usr/bin/g++-13 -DCMAKE_CXX_COMPILER=/usr/bin/g++-13
6. cmake --build build
7. cmake --install ./build --prefix ./out

After these steps you will see ethrecover and btcrecover executables in ./out directory.
