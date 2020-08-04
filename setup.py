from setuptools import setup, find_packages

setup(
    name="input-event-daemon",
    version="0.1",
    entry_points={
        'console_scripts': [
            "input-event-daemon = input-event-daemon:main"
        ]
    },
    install_requires=['evdev>=1.2.0', 'pyudev'],
    author="Nicolas Granger",
    author_email="nicolas.granger.m@gmail.com",
    description="A daemon to monitor key inputs and trigger user-defined commands",
    keywords="keybindings evdev linux daemon",
    url="https://github.com/nlgranger/input-event-daemon",
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: BSD License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3',
        'Environment :: No Input/Output (Daemon)'
    ]
)