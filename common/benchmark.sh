#!/bin/bash

# Benchmark CPU
echo "Running CPU Benchmark..."
echo "CPU Usage (before benchmark):"
mpstat 1 1

echo "Starting CPU Stress Test..."
stress --cpu 4 --timeout 30s
echo "CPU Stress Test Complete."

# Benchmark Memory
echo "Running Memory Benchmark..."
echo "Memory Usage (before benchmark):"
free -h

echo "Starting Memory Stress Test..."
stress --vm 2 --vm-bytes 256M --timeout 30s
echo "Memory Stress Test Complete."

# Benchmark Disk
echo "Running Disk Benchmark..."
echo "Disk Usage (before benchmark):"
df -h

echo "Starting Disk Write Benchmark..."
dd if=/dev/zero of=testfile bs=1M count=1024 conv=fdatasync
echo "Disk Write Benchmark Complete."

# Remove test file after disk benchmark
rm testfile

echo "Benchmarking Complete."

