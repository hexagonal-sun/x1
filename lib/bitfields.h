#pragma once

#define DEFBITFLAG(name, shift, member, type)           \
    static inline void set_flag_##name(type *obj)       \
    {                                                   \
        obj->member |= (1 << (shift));                  \
    }                                                   \
                                                        \
    static inline void clr_flag_##name(type *obj)       \
    {                                                   \
        obj->member &= ~(1 << (shift));                 \
    }                                                   \
                                                        \
    static inline int get_flag_##name(type *obj)        \
    {                                                   \
        return (obj->member >> (shift)) & 0x1;          \
    }
