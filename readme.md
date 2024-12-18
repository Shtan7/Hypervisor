# Hypervisor : RU

## Краткое описание.

Hypervisor - это гипервизор второго типа, который виртуализирует уже запущенную систему. 
Для запуска данного гипервизора вам необходима система Windows 10, а так же интеловский
процессор с поддержкой vt-x и ept технологий.

Теоретический функционал и возможности подобной программы весьма обширны: 
- Перехват широкого списка процессорных инструкций с полной возможностью
кастомизации их поведения. В качестве примера можно привести перехват RDMSR,
который позволит контролировать видимое содержимое регистра для гостевой системы;
- Перехват исключений процессора;
- Возможность инжекта исключений процессора и прерываний;
- Возможность установки невидимых брейкпоинтов на запись, чтение, исполнение;
- Возможность установки невидимых хуков исполнямого кода. POC данной фичи продемонстрирован в проекте на примере хука функции NtCreateFile без триггера Patch Guard. 

## Особенности реализации проекта.

В данном проекте используется порт C++ исключений. Так же реализован минимально
необходимый функционал, обеспечивающий возможность полноценной работы большой 
части стандартной библиотеки C++. Как минимум STL поддерживается. 

Ссылки на источники, с которых был взят порт плюсовых исключений:
- https://github.com/DymOK93/KTL
- https://github.com/avakar/vcrtl

В виду невозможности использования стандартных путей аллокации памяти в некоторых частях кода, 
а именно в тех, которые исполняются в так называемом root моде (режим с выключенными прерываниями), 
был реализован простейший кастомный аллокатор, основанный на TLSF allocator алгоритме.

В проекте заданы настройки сборки, которые генерируют исполняемый образ, поддерживающий
запуск кода при помощи техники 'driver manual mapping', что накладывает на код определенные
ограничения. Так драйвер не может создать device object для проведения I/O операций с юзер
модом. Обойти данное ограничение возможно, например, хукнув любую редко используемую SSDT
функцию, что позволит осуществлять связь драйвера с юзер модом при помощи обычного SYSCALL.
К преимуществам подобного подхода относится возможность использовать гипервизор без необходимости
вводить Windows в тестовый режим, где можно загружать драйвера без цифровой подписи кода.

## О невидимых хуках исполняемого кода.

Для реализации данной фичи используется возможность эмуляции MMIO при помощи EPT технологии.
У целевой страницы с кодом создается двойник, который будет указывать на измененную версию кода
с хуком в начале функции. Целевая страница заменяется измененной, а так же убирается бит доступа 
на чтение и запись, но оставляется бит доступа на исполнение. При попытке чтения хукнутого кода 
(например при проверке целостности ядра Patch Guard'ом) происходит EPT violation, которое ловит 
гипервизор. Далее осуществляется временный подмен измененной версии страницы на оригинальную. 
Таким образом достигается поведение, при котором при доступе к одному виртуальному адресу в разных 
обстоятельствах можно получить разный физический адрес.

Для демонстрации EPT хука в main.cpp в setup_hooks происходит хук SSDT функции 'NtCreateFile'.
Оригинальная функция подменяется хукнутой, в которой осуществляется проверка имени открываемого
объекта. Если имя содержит в себе подстроку 'open_me', то будет вовзращен статус 'ACCESS_DENIED'.

## Сборка проекта.

Для полноценной сборки вам будет необходимо провести рекурсивное клонирование репозитория.
Далее необходимо собрать статическую kernel версию 'Zydis' при помощи Visual Studio проекта,
который находится по пути '\zydis\msvc\Zydis.sln'. Так же необходимо иметь установленный
Windows Driver Kit и Visual Studio 2019, т.к. на момент написания данного readme
WDK еще не портирован для Visual Studio 2022.

# Hypervisor : EN

## A brief description.

Hypervisor is a type 2 hypervisor that virtualizes an already running system. To run this hypervisor, 
you need the Windows 10 system, as well as an Intel processor with vt-x and ept support.

The theoretical functionality and capabilities of the program are very extensive:
- Interception of a wide list of cpu instructions with a full customization of their behavior. 
An example is the RDMSR intercept which allows you to control the visible contents of the register 
for a guest system.
- Interception of processor exceptions;
- The ability to inject processor exceptions or interrupts;
- The ability to set stealth breakpoints for writing, reading, execution;
- The ability to install stealth hooks of the executable code. POC of this feature is implemented as a hook of the NtCreateFile function, and this hook doesn't trigger Patch Guard.

## Features of the project implementation.

This project uses the C++ runtime port which allows you to use C++ exceptions and a big part of the C++ standart library. At least, you can use STL.

Links to repositories from which the port of C++ exceptions was taken:
- https://github.com/DymOK93/KTL
- https://github.com/avakar/vcrtl

You can't use standard ways of memory allocation in the hypervisor root mode, so a simple memory 
allocator was implemented. The allocator uses the 'TLSF allocator' algorithm.

The project generates an executable image that can be run using manual mapping.
This imposes certain restrictions on the code. You can't create a device object for I\O operations 
with user mode. This can be fixed with a SSDT hook which will allow you to perform a connection
with user mode using the simple SYSCALL instruction. The benefits of this approach include the ability 
to use the hypervisor without having to put Windows into the test mode, where drivers can be loaded without the digital sign.

## About stealth hooks of executable code.

To implement this feature, MMIO emulation with EPT is used. A copy with a hook is created for the original page.
Hypervisor clears the target PFN read and write bits and replaces it with the clone. Such a page can be freely 
executed, but not read or written. When Patch Guard checks the integrity of the kernel a read is attempted and the EPT violation 
occurs. After that, the hypervisor temporarily replaces the changed page with the original one. Thus, one virtual 
address leads to different physical addresses in different conditions.

In main.cpp you can find example of this technique. setup_hooks performs the hook of the SSDT function 'NtCreateFile'.
The new function checks an object's name. If it contains substring 'open_me' then the function returns status 'ACCESS_DENIED'.
If you open a file with this substring in the name, you will get an access error.

## The project build.

For a successful build, you need to recursively clone the repository. Next, you need to build Zydis with the
Visual Studio project which path is '\zydis\msvc\Zydis.sln'. You also need to have WDK and Visual Studio 2019 installed.
Visual Studio 2019 because WDK wasn't ported to Visual Studio 2022 at the time of writing the readme.
