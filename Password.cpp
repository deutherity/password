#pragma once // since it's included in templates.hpp
#include "Password.hpp"
#include "QuotedIO.hpp"
#include "genpw.hpp"
#include "gensalt.hpp"
#include "hex.hpp"
#include <cstring>

template <typename CharT>
Password<CharT>::Password(str_t &&service, const int id, str_t &&description,
                          str_t &&t_add_alphabet)
    : m_service(std::move(service)), m_id(id),
      m_add_alphabet(std::move(t_add_alphabet)),
      m_description(std::move(description)) {}

template <typename CharT>
Password<CharT> &Password<CharT>::operator=(const Password<CharT> &other) {
    m_service = other.m_service;
    std::memcpy(m_salt, other.m_salt, other.m_saltlen);
    m_saltlen = other.m_saltlen;
    m_description = other.m_description;
    m_id = other.m_id;
}

template <typename CharT>
Password<CharT> &Password<CharT>::operator=(Password<CharT> &&other) noexcept {
    m_service = std::move(other.m_service);
    m_salt = other.m_salt;
    m_saltlen = other.m_saltlen;
    m_description = std::move(other.m_description);
    m_id = other.m_id;
    other.m_salt = nullptr;
    other.m_saltlen = 0;
    other.m_id = -1;
}

template <typename CharT>
Password<CharT>::Password(Password<CharT> &&other) noexcept
    : m_service(std::move(other.m_service)), m_salt(other.m_salt),
      m_saltlen(other.m_saltlen), m_description(std::move(other.m_description)),
      m_id(other.m_id) {
    other.m_salt = nullptr;
    other.m_saltlen = 0;
    other.m_id = -1;
}

template <typename CharT>
Password<CharT>::Password(const Password<CharT> &other)
    : m_service(other.m_service), m_saltlen(other.m_saltlen),
      m_description(other.m_description), m_id(other.m_id) {
    if (m_saltlen) {
        m_salt = new uchar[m_saltlen];
        std::memcpy(m_salt, other.m_salt, m_saltlen);
    }
}

template <typename CharT> void Password<CharT>::makeSalt() {
    Salt foo;
    gensalt(&foo);
    this->m_salt = foo.data;
    this->m_saltlen = foo.saltlen;
}

template <typename CharT> Password<CharT>::~Password() { delete[] m_salt; }

template <typename CharT>
std::basic_istream<CharT> &operator>>(std::basic_istream<CharT> &input,
                                      Password<CharT> &that) {
    short has_salt;
    input >> that.m_id >> QuotedInput(that.m_service) >> has_salt >>
        QuotedInput(that.m_description) >> QuotedInput(that.m_add_alphabet);
    if (has_salt) {
        char saltbuf[SALTLEN * 2 + 1];
        input >> saltbuf;
        std::size_t saltlen = std::strlen(saltbuf) / 2;
        uchar *foo = new uchar[saltlen];
        for (std::size_t i = 0; i < saltlen; ++i) {
            foo[i] = unhex(saltbuf + 2 * i);
        }
        that.moveSalt(foo, saltlen);
    }
    return input;
}

template <typename CharT>
std::basic_ostream<CharT> &operator<<(std::basic_ostream<CharT> &output,
                                      const Password<CharT> &that) {
    output << that.m_id << ' ' << QuotedOutput<CharT>(that.m_service) << ' '
           << ((that.m_saltlen) ? 1 : 0) << '\n';
    output << QuotedOutput<CharT>(that.m_description) << '\n'
           << QuotedOutput(that.m_add_alphabet);
    if (that.m_saltlen) {
        output.put('\n');
        hexByte chars;
        const uchar *salt = that.getSalt();
        for (std::size_t i = 0; i < that.m_saltlen; ++i) {
            chars = hex(salt[i]);
            output.put(chars.h);
            output.put(chars.t);
            output.flush();
        }
    }
    return output;
}

template <typename CharT>
void Password<CharT>::setSalt(const uchar *t_salt,
                              const std::size_t t_saltlen) {
    delete[] m_salt;
    this->m_salt = new uchar[t_saltlen];
    this->m_saltlen = t_saltlen;
    std::memcpy(this->m_salt, t_salt, t_saltlen);
}

template <typename CharT>
void Password<CharT>::moveSalt(uchar *t_salt, const std::size_t t_saltlen) {
    delete[] m_salt;
    this->m_salt = t_salt;
    this->m_saltlen = t_saltlen;
}

template <typename CharT> const uchar *Password<CharT>::getSalt() const {
    return this->m_salt;
}

template <typename CharT>
std::string
Password<CharT>::cook(const std::basic_string_view<CharT> &passwd) const {

    return "YEP COOK";
}