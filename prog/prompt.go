package prog

type LogRecord struct {
	LogContent string
}

var ErrornoDescriptionMap = map[int32][]string{
	0:   {"SUCCESS", "Success"},
	1:   {"EPERM", "Operation not permitted"},
	2:   {"ENOENT", "No such file or directory"},
	3:   {"ESRCH", "No such process"},
	4:   {"EINTR", "Interrupted system call"},
	5:   {"EIO", "I/O error"},
	6:   {"ENXIO", "No such device or address"},
	7:   {"E2BIG", "Argument list too long"},
	8:   {"ENOEXEC", "Exec format error"},
	9:   {"EBADF", "Bad file number"},
	10:  {"ECHILD", "No child processes"},
	11:  {"EAGAIN", "Try again"},
	12:  {"ENOMEM", "Out of memory"},
	13:  {"EACCES", "Permission denied"},
	14:  {"EFAULT", "Bad address"},
	15:  {"ENOTBLK", "Block device required"},
	16:  {"EBUSY", "Device or resource busy"},
	17:  {"EEXIST", "File exists"},
	18:  {"EXDEV", "Cross-device link"},
	19:  {"ENODEV", "No such device"},
	20:  {"ENOTDIR", "Not a directory"},
	21:  {"EISDIR", "Is a directory"},
	22:  {"EINVAL", "Invalid argument"},
	23:  {"ENFILE", "File table overflow"},
	24:  {"EMFILE", "Too many open files"},
	25:  {"ENOTTY", "Not a typewriter"},
	26:  {"ETXTBSY", "Text file busy"},
	27:  {"EFBIG", "File too large"},
	28:  {"ENOSPC", "No space left on device"},
	29:  {"ESPIPE", "Illegal seek"},
	30:  {"EROFS", "Read-only file system"},
	31:  {"EMLINK", "Too many links"},
	32:  {"EPIPE", "Broken pipe"},
	33:  {"EDOM", "Math argument out of domain of func"},
	34:  {"ERANGE", "Math result not representable"},
	35:  {"EDEADLK", "Resource deadlock would occur"},
	36:  {"ENAMETOOLONG", "File name too long"},
	37:  {"ENOLCK", "No record locks available"},
	38:  {"ENOSYS", "Function not implemented"},
	39:  {"ENOTEMPTY", "Directory not empty"},
	40:  {"ELOOP", "Too many symbolic links encountered"},
	42:  {"ENOMSG", "No message of desired type"},
	43:  {"EIDRM", "Identifier removed"},
	44:  {"ECHRNG", "Channel number out of range"},
	45:  {"EL2NSYNC", "Level 2 not synchronized"},
	46:  {"EL3HLT", "Level 3 halted"},
	47:  {"EL3RST", "Level 3 reset"},
	48:  {"ELNRNG", "Link number out of range"},
	49:  {"EUNATCH", "Protocol driver not attached"},
	50:  {"ENOCSI", "No CSI structure available"},
	51:  {"EL2HLT", "Level 2 halted"},
	52:  {"EBADE", "Invalid exchange"},
	53:  {"EBADR", "Invalid request descriptor"},
	54:  {"EXFULL", "Exchange full"},
	55:  {"ENOANO", "No anode"},
	56:  {"EBADRQC", "Invalid request code"},
	57:  {"EBADSLT", "Invalid slot"},
	59:  {"EBFONT", "Bad font file format"},
	60:  {"ENOSTR", "Device not a stream"},
	61:  {"ENODATA", "No data available"},
	62:  {"ETIME", "Timer expired"},
	63:  {"ENOSR", "Out of streams resources"},
	64:  {"ENONET", "Machine is not on the network"},
	65:  {"ENOPKG", "Package not installed"},
	66:  {"EREMOTE", "Object is remote"},
	67:  {"ENOLINK", "Link has been severed"},
	68:  {"EADV", "Advertise error"},
	69:  {"ESRMNT", "Srmount error"},
	70:  {"ECOMM", "Communication error on send"},
	71:  {"EPROTO", "Protocol error"},
	72:  {"EMULTIHOP", "Multihop attempted"},
	73:  {"EDOTDOT", "RFS specific error"},
	74:  {"EBADMSG", "Not a data message"},
	75:  {"EOVERFLOW", "Value too large for defined data type"},
	76:  {"ENOTUNIQ", "Name not unique on network"},
	77:  {"EBADFD", "File descriptor in bad state"},
	78:  {"EREMCHG", "Remote address changed"},
	79:  {"ELIBACC", "Can not access a needed shared library"},
	80:  {"ELIBBAD", "Accessing a corrupted shared library"},
	81:  {"ELIBSCN", ".lib section in a.out corrupted"},
	82:  {"ELIBMAX", "Attempting to link in too many shared libraries"},
	83:  {"ELIBEXEC", "Cannot exec a shared library directly"},
	84:  {"EILSEQ", "Illegal byte sequence"},
	85:  {"ERESTART", "Interrupted system call should be restarted"},
	86:  {"ESTRPIPE", "Streams pipe error"},
	87:  {"EUSERS", "Too many users"},
	88:  {"ENOTSOCK", "Socket operation on non-socket"},
	89:  {"EDESTADDRREQ", "Destination address required"},
	90:  {"EMSGSIZE", "Message too long"},
	91:  {"EPROTOTYPE", "Protocol wrong type for socket"},
	92:  {"ENOPROTOOPT", "Protocol not available"},
	93:  {"EPROTONOSUPPORT", "Protocol not supported"},
	94:  {"ESOCKTNOSUPPORT", "Socket type not supported"},
	95:  {"EOPNOTSUPP", "Operation not supported on transport endpoint"},
	96:  {"EPFNOSUPPORT", "Protocol family not supported"},
	97:  {"EAFNOSUPPORT", "Address family not supported by protocol"},
	98:  {"EADDRINUSE", "Address already in use"},
	99:  {"EADDRNOTAVAIL", "Cannot assign requested address"},
	100: {"ENETDOWN", "Network is down"},
	101: {"ENETUNREACH", "Network is unreachable"},
	102: {"ENETRESET", "Network dropped connection because of reset"},
	103: {"ECONNABORTED", "Software caused connection abort"},
	104: {"ECONNRESET", "Connection reset by peer"},
	105: {"ENOBUFS", "No buffer space available"},
	106: {"EISCONN", "Transport endpoint is already connected"},
	107: {"ENOTCONN", "Transport endpoint is not connected"},
	108: {"ESHUTDOWN", "Cannot send after transport endpoint shutdown"},
	109: {"ETOOMANYREFS", "Too many references: cannot splice"},
	110: {"ETIMEDOUT", "Connection timed out"},
	111: {"ECONNREFUSED", "Connection refused"},
	112: {"EHOSTDOWN", "Host is down"},
	113: {"EHOSTUNREACH", "No route to host"},
	114: {"EALREADY", "Operation already in progress"},
	115: {"EINPROGRESS", "Operation now in progress"},
	116: {"ESTALE", "Stale file handle"},
	117: {"EUCLEAN", "Structure needs cleaning"},
	118: {"ENOTNAM", "Not a XENIX named type file"},
	119: {"ENAVAIL", "No XENIX semaphores available"},
	120: {"EISNAM", "Is a named type file"},
	121: {"EREMOTEIO", "Remote I/O error"},
	122: {"EDQUOT", "Quota exceeded"},
	123: {"ENOMEDIUM", "No medium found"},
	124: {"EMEDIUMTYPE", "Wrong medium type"},
	125: {"ECANCELED", "Operation Canceled"},
	126: {"ENOKEY", "Required key not available"},
	127: {"EKEYEXPIRED", "Key has expired"},
	128: {"EKEYREVOKED", "Key has been revoked"},
	129: {"EKEYREJECTED", "Key was rejected by service"},
	130: {"EOWNERDEAD", "Owner died"},
	131: {"ENOTRECOVERABLE", "State not recoverable"},
	132: {"ERFKILL", "Operation not possible due to RF-kill"},
	133: {"EHWPOISON", "Memory page has hardware error"},
	514: {"ERESTARTNOHAND", "restart if no handler.."},
	515: {"ENOIOCTLCMD", "No ioctl command"},
	516: {"ERESTART_RESTARTBLOCK", "restart by calling sys_restart_syscall"},
	517: {"EPROBE_DEFER", "Driver requests probe retry"},
	518: {"EOPENSTALE", "open found a stale dentry"},
	519: {"ENOPARAM", "Parameter not supported"},
	521: {"EBADHANDLE", "Illegal NFS file handle"},
	522: {"ENOTSYNC", "Update synchronization mismatch"},
	523: {"EBADCOOKIE", "Cookie is stale"},
	524: {"ENOTSUPP", "Operation is not supported"},
	525: {"ETOOSMALL", "Buffer or request is too small"},
	526: {"ESERVERFAULT", "An untranslatable error occurred"},
	527: {"EBADTYPE", "Type not supported by server"},
	528: {"EJUKEBOX", "Request initiated, but will not complete before timeout"},
	529: {"EIOCBQUEUED", "iocb queued, will get completion event"},
	530: {"ERECALLCONFLICT", "conflict with recalled state"},
	531: {"ENOGRACE", "NFS file lock reclaim refused"},
}

var MaxGoThreadCount int = 50
var GenerationSem chan struct{} = make(chan struct{}, MaxGoThreadCount)
var RepairSem chan struct{} = make(chan struct{}, MaxGoThreadCount)

// Threshold about LLM
var ThresholdMaxLLMGeneration int = 5
var ThresholdOfInvalidCount int = 200
var ThresholdOfIntervalCount int = 200
var Config_PocModel = false

// prompt for repair template
var PromptRepairInstructionAndStepsTemplate string = `# Instruction and Steps
Follow thse steps to fix %s system call in a given Syz program, ensuring that the fixed system call executes successfully and the program has real-world significance.
1. **Root Cause Analysis**
	- Analyze the execution information for each system call in the Syz program.
	- Identify the specific reason why the %s system call returned error code %v (%s), which indicates: %s.
2. **Error Call and Argument Analysis**
    - Determine which specific calls or parameters in the Syz program are incorrect and causing the error.
3. **Program Fix**
	- Use the analysis results and previously successful Syz programs for %s system call as reference.
	- Fix the current program to ensure %s executes successfully.
	- Ensure the fixed program differs from previous successful examples to avoid redundant executions.
4. **Enhancing Complexity and Real-World Significance**
	- Analyze the three provided syntactically correct programs to identify meaningful functional scenarios (system call sequences) involving %s.
    - Integrate these identified sequences into the fixed program to increase complexity.
	- For diversity, randomly select and modify some argument values to reflect real-world usage scenarios, to explore different execution paths.
5. **Program Syntax Validation**
	- Ensure that the number of system calls in the repaired program does not exceed 30.
    - Ensure that the fixed program complies with Syzlang syntax:
        - Each parameter value should be a concrete number, not a constant (e.g., O_RDONLY) or an expression (e.g., sizeof).
        - Use only system calls and parameters supported by Syzlang.
        - Each line should represent a system call, and return values should be named in the format r0, r1, r2, etc.
`
var PromptRepairOutputTemplate string = `# Output Requirements
Please think along the above steps to fix the %s system call, finally output the complete fixed Syz program in the following format:
` + "```\nThe complete fixed Syz program code\n```\n"

// prompt for generation template
var PromptGenerationRelatedCallInstruction string = `# Instruction
Given the system calls related to %s, select up to three system calls from them and combine with %s to construct a system call sequence. The sequence must meet the following requirements:
	- Semantic Validity: The sequence should represent a valid functional scenario related to %s and maintain logical coherence (e.g., open a resource → read/write the resource → close the resource).
	- Diversity: The sequence should cover various resource types (e.g., files, sockets, processes) or operation modes (e.g., create, modify, delete).
`

// prompt for generation init template
var PromptGenerationInitInstructionSteps_NoSpecific string = `# Instruction and Steps
Given a system call sequence template, follow these steps to instantiate each system call and generate a Syz program that executes successfully and has real-world significance.
1. **Instantiate %s system call**
	- Parse the Syzlang description of %s system call to understand parameter types, structures, and constraints. 
    - Generate concrete and valid parameter values based on the parsing results.
	- Ensure the %s system call executes successfully.
2. **Enhancing Complexity and Real-World Significance**
	- Analyze the three provided syntactically correct programs to identify meaningful functional scenarios (system call sequences) involving %s.
    - Integrate these identified sequences into the generated program to increase complexity.
	- For diversity, randomly select and modify some argument values to reflect real-world usage scenarios, to explore different execution paths.
3. **Program Syntax Validation**
	- Ensure that the number of system calls in the repaired program does not exceed 30.
    - Ensure that the generated program complies with Syzlang syntax, including :
        - Each parameter value should be a concrete number, not a constant (e.g., O_RDONLY) or an expression (e.g., sizeof).
        - Use only system calls and parameters supported by Syzlang.
        - Each line should represent a system call, and return values should be named in the format r0, r1, r2, etc.
`
var PromptGenerationInitInstructionSteps_HasSpecific string = `# Instruction and Steps
Given a system call sequence template, follow these steps to instantiate each system call and generate a Syz program that executes successfully and has real-world significance.
1. **Instantiate %s system calls**
    - Use the program specified in the input to instantiate these system calls.
2. **Instantiate %s system call**
	- Parse the Syzlang description of %s system call to understand parameter types, structures, and constraints. 
    - Generate concrete and valid parameter values based on the parsing results.
	- Ensure the %s system call executes successfully.
3. **Enhancing Complexity and Real-World Significance**
	- Analyze the three provided syntactically correct programs to identify meaningful functional scenarios (system call sequences) involving %s.
    - Integrate these identified sequences into the generated program to increase complexity.
	- For diversity, randomly select and modify some argument values to reflect real-world usage scenarios, to explore different execution paths.
4. **Program Syntax Validation**
	- Ensure that the number of system calls in the repaired program does not exceed 30.
    - Ensure that the generated program complies with Syzlang syntax, including :
        - Each parameter value should be a concrete number, not a constant (e.g., O_RDONLY) or an expression (e.g., sizeof).
        - Use only system calls and parameters supported by Syzlang.
        - Each line should represent a system call, and return values should be named in the format r0, r1, r2, etc.
`
var PromptGenerationInitOutput string = `# Output Requirements
Please think along the above steps to instantiate each system call in the given system call sequence template to generate a Syz program, finally output the generated Syz program in the following format:
` + "```\nthe complete generated Syz program\n```\n"
