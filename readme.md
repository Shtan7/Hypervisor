# Hypervisor : RU

## Краткое описание.

Hypervisor - это гипервизор второго типа, который виртуализирует уже запущенную систему. 
Для запуска данного гипервизора вам необходима система Windows 10, а так же интеловский
процессор с поддержкой vt-x и ept технологий.

Теоретический функционал и возможности подобной программы весьма обширны: 
- Перехват широкого списка ассемблерных инструкций с полной возможностью
кастомизации их поведения. В качестве примера можно привести перехват RDMSR,
который позволит контролировать видимое содержимое регистра для гостевой системы;
- Перехват исключений процессора;
- Возможность инжекта исключений процессора;
- Возможность установки невидимых брейкпоинтов на запись, чтение, исполнение;
- Возможность установки невидимых хуков исполнямого кода. Данная фича реализована
и используется в проекте для хукинга ядерных функций системы без триггера BSOD'а
от Patch Guard'а. 

## Особенности реализации проекта.

В данном проекте используется порт C++ исключений. Так же реализован минимально
необходимый функционал, обеспечивающий возможность полноценной работы большой 
части стандартной библиотеки C++. Как минимум STL поддерживается. 

Ссылки на источники, с которых был взят порт плюсовых исключений:
- https://github.com/DymOK93/KTL
- https://github.com/avakar/vcrtl

В виду невозможности использования стандартных путей аллокации памяти в некоторых частях кода, 
а именно в тех, которые исполняются в так называемом root моде (режим с выключенными прерываниями), 
был реализован простейший кастомный аллокатор, основанный на buddy memory allocation алгоритме.

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
с хуком в начале функции. У оригинальной страницы убирается бит доступа, позволяющий исполнение
и при попытке запуска кода происходит EPT violation, которое ловит гипервизор. Далее осуществляется
временная подмена оригинальной страницы на измененную. Таким образом достигается поведение, при котором
при доступе к одному виртуальному адресу в разных обстоятельствах можно получить разный физический адрес без
триггера Patch Guard. 

Для демонстрации EPT хука в main.cpp в setup_hooks происходит хук SSDT функции 'NtCreateFile'.
Оригинальная функция подменяется хукнутой, в которой осуществляется проверка имени открываемого
объекта. Если имя содержит в себе подстроку 'open_me', то будет вовзращен статус 'ACCESS_DENIED',
а при открытии, например, файла с данной подстрокой в имени, будет выдана ошибка доступа.

## Сборка проекта.

Для полноценной сборки вам будет необходимо провести рекурсивное клонирование репозитория.
Далее необходимо собрать статическую kernel версию 'Zydis' при помощи Visual Studio проекта,
который находится по пути '\zydis\msvc\Zydis.sln'. Так же необходимо иметь установленный
Windows Driver Kit и Visual Studio 2019, т.к. на момент написания данного readme
WDK еще не портирован для Visual Studio 2022.

# Hypervisor : EN

## Brief description.

Hypervisor is a type 2 hypervisor that virtualizes an already running system. To run this hypervisor, 
you need a Windows 10 system, as well as an Intel processor with vt-x and ept support.

The theoretical functionality and capabilities of the program are very extensive:
- Interception of a wide list of assembler instructions with full customization of their behavior. 
An example is the RDMSR intercept, which will allow you to control the visible contents of the register 
for the guest system.
- Interception of processor exceptions;
- Ability to inject processor exceptions;
- Ability to set stealth breakpoints for writing, reading, execution;
- Ability to install stealth hooks of the executable code. This feature is implemented and used in the 
project for hooking the kernel functions of the system without the BSOD trigger from Patch Guard.

## Features of the project implementation.

This project uses the C++ port of exceptions. The minimum necessary functionality is also implemented, 
which ensures the full operation of a large part of the C++ standard library. At least STL is supported.

Links to repositories from which the port of C++ exceptions was taken:
- https://github.com/DymOK93/KTL
- https://github.com/avakar/vcrtl

You can't use standard ways of memory allocation in hypervisor root mode, so simple memory 
allocator was implemented. Allocator uses 'buddy memory allocation' algorithm.

The project generates an executable image that can be run using manual mapping.
This imposes certain restrictions on the code. You can't create device object for I\O operations 
with user mode. This can be fixed with a SSDT hook which will allow you to perform connection
with user mode using a simple SYSCALL instruction. The benefits of this approach include the ability 
to use the hypervisor without having to put Windows into test mode, where drivers can be loaded without digital sign.

## About stealth hooks of executable code.

To implement this feature, MMIO emulation with EPT is used. A copy with a hook is created for the original page.
Hypervisor clears the original page's execution bit. This leads to EPT violations that the hypervisor catches.
Next, a temporary replacement of the original page with its copy is performed. Thus, one virtual address leads to 
different physical addresses in different conditions.

In main.cpp you can find example of this technique. setup_hooks performs hook of the SSDT function 'NtCreateFile'.
New function checks object's name. If it contains substring 'open_me' then function returns status 'ACCESS_DENIED'.
If you open a file with this substring in the name, you will get an access error.

## Project build.

For a successful build, you need to recursively clone the repository. Next, you need to build the Zydis with
Visual Studio project which path is '\zydis\msvc\Zydis.sln'. You also need to have WDK and Visual Studio 2019 installed.
Visual Studio 2019 because the WDK has not been ported to Visual Studio 2022 at the time of writing the readme.