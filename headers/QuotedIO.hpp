#pragma once

#include <iostream>
#include <string>

template <typename CharT = char, CharT delimChar = '|', CharT quoteChar = '/'>
class QuotedOutput {
  private:
    const std::basic_string<CharT> &m_buffer;

  public:
    QuotedOutput(const std::basic_string<CharT> &t_buffer)
        : m_buffer(t_buffer) {}
    /*
    QuotedOutput(QuotedOutput<CharT> && t_other) noexcept = default;
    QuotedOutput(const QuotedOutput<CharT> & t_other) noexcept = default;
    QuotedOutput<CharT> & operator= (const QuotedOutput<CharT> & t_other)
    noexcept = default; QuotedOutput<CharT> & operator= (QuotedOutput<CharT> &&
    t_other) noexcept = default;
    */
    /*
    std::basic_string<CharT> getBuffer() const noexcept { return m_buffer; }
    std::basic_string<CharT> &&moveBuffer() noexcept { return
    std::move(m_buffer);
    }
    */

    friend std::basic_ostream<CharT> &
    operator<<(std::basic_ostream<CharT> &output,
               const QuotedOutput<CharT, delimChar, quoteChar> &that) {
        output << delimChar;
        for (CharT i : that.m_buffer) {
            if (i == quoteChar || i == delimChar)
                output.put(quoteChar);
            output.put(i);
        }
        output << delimChar;
        return output;
    }
    /*
            friend std::basic_istream<CharT> & operator
       >>(std::basic_istream<CharT> &input, QuotedOutput<CharT, delimChar,
       quoteChar> & that)
            {
                input.ignore(20000, delimChar);
                CharT i;

                that.m_buffer.clear();
                while (input.good())
                {
                    i = (char)input.get();
                    if (i == delimChar)
                        break;
                    if (i == quoteChar)
                        i = (char)input.get();
                    that.m_buffer += i;
                }
                return input;
            }
            */
};

template <typename CharT = char, CharT delimChar = '|', CharT quoteChar = '/'>
class QuotedInput {
  private:
    std::basic_string<CharT> &m_buffer;

  public:
    QuotedInput(std::basic_string<CharT> &t_buffer) : m_buffer(t_buffer) {}
    friend std::basic_istream<CharT> &
    operator>>(std::basic_istream<CharT> &input,
               QuotedInput<CharT, delimChar, quoteChar> &&that) {
        input.ignore(20000, delimChar);
        CharT i;

        that.m_buffer.clear();
        while (input.good()) {
            i = (char)input.get();
            if (i == delimChar)
                break;
            if (i == quoteChar)
                i = (char)input.get();
            that.m_buffer += i;
        }
        return input;
    }
};
/*

template <typename CharT, CharT delimChar, CharT quoteChar>
std::basic_istream<CharT> &
operator>>(std::basic_istream<CharT> &input, QuotedOutput<CharT, delimChar,
quoteChar> &that);

template <typename CharT, CharT delimChar, CharT quoteChar>
inline std::basic_ostream<CharT>&
operator>>(std::basic_ostream<CharT> &output, const QuotedOutput<CharT,
delimChar, quoteChar>& that);
*/