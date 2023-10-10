# AutoMemProc

AutoMemProc is a tool designed to simplify and streamline the process of analyzing memory dumps. Its main goal is to act  as an interface for the Volatility 3 framework version 2.5.0, enhancing the user experience with automation and user-friendly prompts.

Certainly! Here's a more detailed breakdown:

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

**Target Audience**:
 - Digital forensics professionals or researchers who often analyze memory dumps.
   Incident responders looking to quickly triage potentially compromised systems.
   Educators or students in cybersecurity courses where memory analysis is a topic.

**Optimized Environment**:
- AutoMemProc is optimized for Unix environments and may not function as intended in other operating systems.

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

## Recommendtion

- Store automemproc.ps1 in the same folder as the imagefile for quick detection.

## Contact

For information or requests, contact:

Issue/Support: 
Twitter: @atiahlaoufi
