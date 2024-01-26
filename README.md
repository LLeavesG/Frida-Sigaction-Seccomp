# Frida-Sigaction-Seccomp
Frida-Sigaction-Seccomp实现对Android APP系统调用的拦截

## 思路和代码来源
>     
[[原创]基于seccomp+sigaction的Android通用svc hook方案 ](https://bbs.kanxue.com/thread-277544.htm)

[[原创]SVC的TraceHook沙箱的实现&无痕Hook实现思路 ](https://bbs.kanxue.com/thread-273160.htm)

[[原创]分享一个Android通用svc跟踪以及hook方案——Frida-Seccomp  ](https://bbs.kanxue.com/thread-271815.htm)

## 原文
* 看雪文章
https://bbs.kanxue.com/thread-280343.htm
  
* 个人博客
https://blog.lleavesg.top/article/Android-Seccomp#c40e15ab4db1407f9e9e0a111631150a

## 使用说明

直接将js注入即可实现对openat的监控，需要在logcat过滤native查看结果

在实战时根据自己需求修改CModule中的`define`，其中`target_nr` 是目标系统调用号。

在拦截到系统调用后会再次进行系统调用，防止再次被拦截，就需要一个寄存器来放一个标识符`SECMAGIC` ，避免反复调用`crash`。`SECMAGIC_POS` 即为对应系统调用所不需要的第一个寄存器，比如`openat`需要三个参数，那么`SECMAGIC_POS` 填3即可，因为寄存器从`x0`开始，`args[3]`即为第四个寄存器。

然后就是在`sig_handler` 中写劫持逻辑。如果想拦截更多的系统调用，就需要重写`seccomp filter` 。

除此之外调用栈等信息，可以参考[[原创]分享一个Android通用svc跟踪以及hook方案——Frida-Seccomp  ](https://bbs.kanxue.com/thread-271815.htm) 阿碧大佬的思路自己添加。
![image](https://github.com/LLeavesG/Frida-Sigaction-Seccomp/assets/57952228/77922b59-5a1a-480d-a20a-496d5589f3a8)


同理也可以实现对mincore的拦截
![image](https://github.com/LLeavesG/Frida-Sigaction-Seccomp/assets/57952228/bdeb84b3-124f-49aa-a3f1-4269178d434f)


 
