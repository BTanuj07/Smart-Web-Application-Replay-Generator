#!/bin/bash

echo "========================================"
echo "HTTP Attack Testing for AttackReplay Pro"
echo "========================================"
echo

echo "Choose testing option:"
echo "1. Simple HTTP Tester (Quick - 10 basic attacks)"
echo "2. Comprehensive HTTP Tester (Full - All attack types)"
echo "3. Exit"
echo

read -p "Enter your choice (1-3): " choice

case $choice in
    1)
        echo
        echo "Running Simple HTTP Tester..."
        echo
        python3 simple_http_tester.py
        ;;
    2)
        echo
        echo "Running Comprehensive HTTP Tester..."
        echo
        python3 http_attack_tester.py
        ;;
    3)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice. Please run the script again."
        ;;
esac

echo
read -p "Press Enter to continue..."