#pragma once
#include "const_password.hpp"
#include <istream>
#include <ostream>
#include <string>
#include <string_view>
#include <cstdint>

template <typename CharT = char> struct Password {
  private:
    uchar *m_salt = nullptr;

  public:
    typedef std::basic_string<CharT> str_t;
    str_t m_service;
    std::size_t m_saltlen = 0;
    int m_id = -1;
    std::uint16_t m_length = 14;
    std::string m_add_alphabet;
    str_t m_description;

    Password() = default;

    Password(str_t &&service, const int id, std::uint16_t length = 14, str_t &&description = "",
             std::string &&t_add_alphabet = "");
    Password(Password &&other) noexcept;
    Password(const Password &other);
    ~Password();

    Password &operator=(Password<CharT> &&other) noexcept;
    Password &operator=(const Password<CharT> &other);
    const uchar *getSalt() const;
    void moveSalt(uchar *t_salt, const std::size_t t_saltlen);
    bool valid() const { return m_id != -1; }
    std::string cook(std::basic_string<CharT> &&realpwd) const;
    void makeSalt();
    void setSalt(const uchar *t_salt, const std::size_t t_saltlen);
};

template <typename CharT>
std::basic_istream<CharT> &operator>>(std::basic_istream<CharT> &input,
                                      Password<CharT> &that);

template <typename CharT>
std::basic_ostream<CharT> &operator<<(std::basic_ostream<CharT> &output,
                                      const Password<CharT> &that);