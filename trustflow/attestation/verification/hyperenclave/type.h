#pragma once
#define RCAST(t, v) reinterpret_cast<t>((v))
#define SCAST(t, v) static_cast<t>((v))
#define CCAST(t, v) const_cast<t>((v))
#define RCCAST(t, v) reinterpret_cast<t>(const_cast<char*>((v)))
#define RCCHAR(v) reinterpret_cast<char*>((v))