# AutoMemProc

AutoMemProc is a tool designed to simplify and streamline the process of analyzing memory dumps. Its main goal is to act  as an interface for the Volatility 3 framework version 2.5.0, enhancing the user experience with automation and user-friendly prompts.

## Target Audience
Digital forensics professionals or researchers who often analyze memory dumps. Incident responders looking to quickly triage potentially compromised systems.
Educators or students in cybersecurity courses where memory analysis is a topic.
   
## Key Features

**User-friendly interface**: AutoMemProc is designed with users in mind. Its straightforward design ensures even those unfamiliar with memory forensic tools can navigate with ease. Key features include:
- **Path Input**: Users can directly specify paths to memory images without navigating through complex file hierarchies.
- **Image Selection**: The tool intelligently detects and lists all available memory images from a specified directory, offering users a simple choice rather than manual file input.
- **Numbered Options**: To simplify choices, menu options are associated with specific numbers, allowing for fast and mistake-free navigation.
- **Command Simplicity**: All commands in AutoMemProc are optimized for clarity, ensuring users don't need extensive documentation to operate the tool.

**Automatic Image Detection**: 
- The tool automatically scans and detects all memory image files in the provided directory.
- It then displays them in an easy-to-read list format, eliminating the need to remember exact file names.

**Saved Paths**:
- For enhanced efficiency, AutoMemProc remembers crucial paths. 
- For instance, once the path to the Volatility executable is set, the tool recalls it for future sessions, reducing repetitive setup time.

**Plugin Interface**: 
- AutoMemProc seamlessly integrates with Volatility.
- After selecting an image, the tool transitions users to a menu dedicated to Volatility plugins. Here, they can pick and execute plugins directly without needing separate command-line inputs.

**Error Handling**: 
- Recognizing that everyone can make mistakes, AutoMemProc is built to handle errors gracefully.
- Whether it's an empty path, an incorrect file format, or any other input error, the tool provides clear feedback and guides users on how to correct the issue.

**Background Job**: 
- To ensure that users don't experience lags or freezes, certain tasks within AutoMemProc are designed to run as background jobs.
- This allows for tasks like large memory image analyses to operate in parallel, ensuring the main application remains responsive at all times.

**Custom Volatility CLI Access**:
- **Seamless Transition to CLI**: AutoMemProc is not just about providing a simplified interface. Recognizing the needs of advanced users or those with specific requirements, the tool offers direct access to the Volatility command-line interface (CLI).
- **Pre-populated Commands**: To save users time and reduce redundant typing, when users enter the CLI section, the tool already includes the paths to the Volatility tool and the chosen memory image in the command prompt. This allows for quicker command input and execution.
- **Flexible Command Execution**: Users can run any command or use any plugin available in Volatility, extending the tool's functionality beyond the pre-defined menu options in AutoMemProc.
- **Exit Option**: For ease of navigation, users can simply type 'exit' to return to the main menu, ensuring they are not stuck in the command-line interface and can easily transition back to the guided interface.

This feature underscores AutoMemProc's commitment to catering to both beginners, who might prefer a structured interface, and advanced users, who might need the flexibility and power of direct CLI access.

## Key Point

- Ensure proper permissions are granted for this tool to execute without errors.
- The results of the plugins are not displayed directly in the terminal. Instead, they are saved as .txt files in the same directory where the image file is stored.
- The Process Dump Plugin, create a folder in the same location as the image file to store its outputs. 
- Some Plugin have the ability to run background job used 'job -s' to check supported plugins.
- Please ensure you do not exit the tool until your background job completed, as exiting while a job is active will terminate the jobs.
- If you would like to view the active background job running using terminal,

 ``` shell
  ps -ef
  ```

## Capabilities

**Unix-Centric Design** 
- AutoMemProc is purpose-built for Unix-based systems. This includes popular Linux distributions such as Ubuntu, CentOS, and Fedora, as well as BSD variants and macOS. Its underlying structure and functionalities are optimized for the Unix environment.

**Windows Memory Image Analysis**
- While the tool operates within a Unix environment, it specializes in analyzing memory images from Windows systems. This dual compatibility makes it versatile for forensic analyses, especially when Windows systems are the subjects of investigation but the analysis is carried out on Unix platforms.

**Single Memory Image**
- The tool is designed to process a single selection of a Windows memory image at a time, ensuring a focused and thorough analysis for each chosen memory image.

## Recommendtion

- Store automemproc.ps1 in the same folder as the imagefile for quick detection.

## Contact

For information or requests, contact:

Issue/Support: 
Twitter: @atiahlaoufi
