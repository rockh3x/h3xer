# H3XER Makefile - Alternative to CMake
# For use when CMake is not available

NVCC = nvcc
CXX = g++

# CUDA architecture (adjust for your GPU)
# RTX 40xx: sm_89, RTX 30xx: sm_86, RTX 20xx: sm_75
CUDA_ARCH = -arch=sm_86

# Optimization flags
NVCC_FLAGS = -O3 --use_fast_math $(CUDA_ARCH) -std=c++17
NVCC_FLAGS += --expt-relaxed-constexpr
CXX_FLAGS = -O3 -std=c++17

# Include paths
INCLUDES = -I./include

# Output directory
BUILD_DIR = build

# Source files
MAIN_SRC = src/main.cu
TEST_SRC = src/test_crypto.cu
EXTRACT_SRC = src/h3xer_extract.cpp

# Targets
all: $(BUILD_DIR) h3xer h3xer_extract h3xer_test

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

h3xer: $(MAIN_SRC)
	$(NVCC) $(NVCC_FLAGS) $(INCLUDES) -o $(BUILD_DIR)/h3xer $(MAIN_SRC)

h3xer_test: $(TEST_SRC)
	$(NVCC) $(NVCC_FLAGS) $(INCLUDES) -o $(BUILD_DIR)/h3xer_test $(TEST_SRC)

h3xer_extract: $(EXTRACT_SRC)
	$(CXX) $(CXX_FLAGS) $(INCLUDES) -o $(BUILD_DIR)/h3xer_extract $(EXTRACT_SRC)

clean:
	rm -rf $(BUILD_DIR)

benchmark: h3xer
	./$(BUILD_DIR)/h3xer -b

test: h3xer_test
	./$(BUILD_DIR)/h3xer_test

.PHONY: all clean benchmark test
