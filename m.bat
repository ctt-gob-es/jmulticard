@echo off
cls
set JAVA_HOME=C:\java\OpenJDK8
set PATH=C:\java\OpenJDK8\bin;C:\java\maven\bin;%PATH%
C:\java\maven\bin\mvn.cmd clean install
