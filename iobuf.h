#pragma once
#include <string>
#include <vector>
#include <stdlib.h>
#include <exception>
#include <stdexcept>
#include <stdint.h>

struct IOBuf {
    std::vector<char> data;
    size_t cursor = 0;

    void operator++(int) {
        cursor++;
    }

    const char* raw() const {
        return data.data();
    }

    const char* cur() const {
        return data.data() + cursor;
    }

    IOBuf& seek(size_t pos) {
        cursor = pos;
        return *this;
    }

    IOBuf& reset() {
        cursor = 0;
        data.clear();
        return *this;
    }

    IOBuf& end() {
        cursor = data.size();
        return *this;
    }

    size_t size() const {
        return data.size();
    }

    size_t capacity() const {
        return data.size() - cursor;
    }

    char read() {
        if(cursor >= data.size()) {
            throw std::runtime_error("invalid read access");
        }
        return data[cursor++];
    }

    int i8() {
        return ((unsigned char)read()) & 0xFF;
    }

    int i16() {
       int a = i8();
       int b = i8();
       return (b << 8) | a; 
    }

    int I16() {
       int a = i8();
       int b = i8();
       return (a << 8) | b; 
    }

    int i32() {
       int a = i8();
       int b = i8();
       int c = i8();
       int d = i8();
       return (d << 24) | (c << 16) | (b << 8) | a;
    }

    int I32() {
       int a = i8();
       int b = i8();
       int c = i8();
       int d = i8();
       return (a << 24) | (b << 16) | (c << 8) | d;
    }

    std::string sz() {
        char c = i8();
        std::string str;
        while(c != 0 && cursor < data.size()) {
            str += ((char)c);
            c = i8();
        }
        return str;
    }

    IOBuf& i8(char c) {
        if(cursor > data.size()) {
            throw std::runtime_error("invalid access");
        } else if(cursor == data.size()) {
            data.push_back(c & 255);
            cursor++;
        } else {
            data[cursor++] = c & 255;
        }
        return *this;
    }
    
    IOBuf& i16(int num) {
        return i8(num).i8(num >> 8);
    }

    IOBuf& I16(int num) {
        return i8(num >> 8).i8(num);
    }

    IOBuf& i32(int num) {
        return i8(num).i8(num >> 8).i8(num >> 16).i8(num >> 24);
    }

    IOBuf& I32(int num) {
        return i8(num >> 24).i8(num >> 16).i8(num >> 8).i8(num);
    }

    IOBuf& sz(const std::string& s) {
        for(char c : s) {
            i8(c);
        }
        return i8(0);
    }

    IOBuf& bytes(const char* buff, size_t len) {
        for(size_t i=0; i < len; i++) {
            i8(buff[i]);
        }
        return *this;
    }

    IOBuf& rewind(size_t back) {
        cursor -= back;
        return *this;
    }

    bool eof() const {
        return cursor >= data.size();
    }

    IOBuf& operator+=(size_t n) {
        cursor += n;
        return *this;
    }

    char& operator[](size_t i) {
        if(i + cursor >= data.size()) {
            throw std::runtime_error("invalid access");
        }
        return data[cursor + i];
    }
};