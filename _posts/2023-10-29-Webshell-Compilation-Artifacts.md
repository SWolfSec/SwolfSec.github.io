---
published: true
layout: post
title: Webshell Compilation Artifacts
subtitle: Understanding Artifacts From the Compilation of Webshells
tags: [webshells]
comments: false
share-img:  https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/java.PNG
---
> By Stephan Wolfert

> **_TL:DR_** Webshells written in compiled languages can provide insights commonly lost when webshells are no longer on disk.

## Why is this important?

According to Wikipedia, a webshell is "a shell-like interface that enables a web server to be accessed remotely for the purposes of cyberattacks". Webshells are a common tool an attacker will use to execute commands on a system. Webshells have many uses whether it is for initial access, lateral movement, persistence and so on. Whether an attacker is attempting any of these attack techniques, some of the artifacts associated with webshells stay fairly consistent. 

In regards to webshells written in compiled languages such as C# and Java, compilation artifacts can be a great resource for investigators. From personal experience, these artifacts can be immensely valuable when dealing with an investigation that occurs after an attacker has cleaned up their tooling or when you are not the first responders to an investigation and artifacts haven't been preserved. In this blog we will briefly discuss these artifacts and hopefully show some simple ways to improve analysis of webshells.  

## What are the artifacts ?

The two webshell types we will focus on are ASPX and JSP. We will show these artifacts on both Windows and Linux systems since modern webshells are often written to account for both and compilation must happen regardless of the Operating System. 

It is important to note that these compilation artifacts are a result of the webserver preparing the code it will execute within the ASPX or JSP webshell. You will notice these artifacts with the legitimate webserver pages as well. For the different compiled languages, the principles described here will stay consistent but there is nuance between them. For ASPX compilation, we will primarily be looking for a Dynamic Link Library ("DLL") file. For JSP compilation, we will look for the java compiled ".class" file. Luckily for investigators, decompilation of these two artifacts are trivial with modern tools. 

## ASPX Webshells 
First taking a look at our ASPX webshell which is hosted on a dotnet application running on a Windows Server.  The name of this basic webshell is `cmdasp.aspx`. 

|![ASPXWebshell](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/ASPXWebshell.PNG)|
|:--:|
|Figure 1: ASPX Webshell used to run `whoami /all`|

We do not need to run any commands through the ASPX webshell in order for compilation to take place. Based on my experience, once the page is visited compilation will begin for ASPX. 

The location of compilation artifacts will vary based on the application but generally searching within the `C:\Windows\Microsoft.NET\Framework\[version]\Temporary ASP.NET Files\` directory will lead you in the right direction.  You will see in figure 2 the directory of our application as an example. 

|![WebshellCompilationFiles](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/WebshellCompilationFiles.PNG)|
|:--:|
|Figure 2: Compilation artifacts for ASPX webshell|

As mentioned previously, there will be many files within these directories that are legitimate files related to the running web application. In our example, the files of interest stand out based on their timestamp. Starting with the file `cmd.aspx.cdcab7d2.compiled`, since if you are unfamiliar with the topic of this blog it was likely the first file that caught your eye.

|![ASPXmetadata](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/ASPXmetadata.PNG)|
|:--:|
|Figure 3: Compilation artifact for ASPX webshell ".compiled"|

Looking at this file in Figure 3, if we wanted to know how this webshell worked, we'd be left guessing. The main value of this file is two fold, the timestamp can give us an indication of when the ASPX webshell was compiled, as well as the name of the DLL which we are most interested in (specified in the assembly parameter). 

Now that we know the DLL name of interest, `App_Web_z01dtudd` we can move to decompiling using a tool named [dnSpy](https://github.com/dnSpy/dnSpy).  Decompilation of dotnet code is fairly trivial, loading the DLL into dnSpy gives us pretty much all we will need. As shown in Figure 4, the functionality of the webshell is easily readable almost instantly. 

|![dnSpy](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/dnSpy.PNG)|
|:--:|
|Figure 4: dnSpy to decompile ASPX webshell DLL artifact|

This process can give us key information on the functionality of the webshell. Why is that important to us? Well, here we see `cmd.exe` as the primary execution method. This can help us identify the child processes to look for under the web worker process i.e. `w3wp.exe` spawning `cmd.exe`. In Figure 5, we used the webshell to execute `powershell.exe` which results in the following process tree. Although `cmd.exe` spawning from `w3wp.exe` should already be on your radar, if a webshell was performing a more novel method of execution we could use the knowledge from the decompiled code to create detections or hunting queries for it. 

|![ASPXProcExp](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/ASPXProcExp.PNG)|
|:--:|
|Figure 5: Process telemetry of the webshell|

Other key important details that could provide context when looking at other artifacts include; Do we need to identify POST or GET requests in the http access logs? Did we identify the ability to proxy commands to the internal network like [reGorg](https://github.com/sensepost/reGeorg)? Are there accounts or hard-coded credentials referenced in the webshell? Is the webshell unique and is there attribution to a specific threat actor associated with it?  These are just a few quick examples of why knowing the functionality is important. 

A quick note on showing the compilation process, there are other cmdline and out files (`z01dtudd.out`) associated with this DLL that show the actual compilation commands executed using `csc.exe` as shown in Figure 6. 

|![OutFile1](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/OutFile1.PNG)|
|![OutFile2](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/OutFile2.PNG)|
|:--:|
|Figure 6: Compilation "out" file showing the actual compilation commands using `csc.exe`|

## JSP Webshells

Now on to JSP webshells, the same principles will apply since we are still looking for evidence of compilation. The methods will vary slightly but in theory stay relatively the same. First we setup our JSP webshell on a Linux webserver running a java application and show it is working. 

|![JSPWebshell](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/JSPWebshell.PNG){:mx-auto.d-block}|
|:--:|
|Figure 7: JSP webshell deployment and execution|

The name of the the webshell here is `cmdjsp.jsp` . Identification of the artifacts related to the JSP webshell will be slightly easier since here the class file of compiled code will include the webshell name. In Figure 8, you can see we are looking for `__cmdjsp.class`. This class file is not typically going to be found in the same directory where the webshell exists (or existed) although the actual location will likely depend on the java application which was running on the server. 

|![CompiledClass](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/CompiledClass.PNG)|
|:--:|
|Figure 8: JSP Class file identified on disk|

Similarly to before, now that we have our compiled class file we can use a tool known as [JD-GUI](http://java-decompiler.github.io/)  to decompile it. Loading the class file into JD-GUI gives us a clear view into the actual code behind the webshell as shown in Figure 9.

|![JD-GUI](https://swolfsec.github.io/assets/img/img_2023-10-29-Webshells/JD-GUI.PNG)|
|:--:|
|Figure 9: Decompiled Java class file from JSP webshell|

Again, here we can see some key details about the functionality of the webshell and anything of interest that can aid in our investigation. 


## Conclusion

The two methods to investigating compiled webshells discussed here are two simple ways to improve your analysis. Webshells can vary significantly from language to language, or complexity to simplicity. Webshells can be extremely difficult to identify depending on the size and scope of the environment and the sophistication of the webshell. Considering the type of webshell you are dealing with and how they work can greatly improve your ability to find them whether they were there historically and/or currently existing. The compilation aspect of ASPX and JSP gives us a bit more information to help track them down.  
