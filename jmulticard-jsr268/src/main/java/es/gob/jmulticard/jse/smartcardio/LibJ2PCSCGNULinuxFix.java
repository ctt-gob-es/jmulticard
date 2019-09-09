package es.gob.jmulticard.jse.smartcardio;

import java.io.File;
import java.util.logging.Logger;

/**
 * Encapsulate fixes regarding the dynamic loading of the pcsclite library on GNU/Linux Systems.
 * statically call LibJ2PCSCGNULinuxFix.fixNativeLibrary() before using a TerminalFactory.
 *
 * @author Frank Cornelis
 * @author Frank Marien
 */
class LibJ2PCSCGNULinuxFix {

  private static final Logger LOGGER = Logger.getLogger(LibJ2PCSCGNULinuxFix.class.getName());

  private static final int PCSC_LIBRARY_VERSION = 1;
  private static final String SMARTCARDIO_LIBRARY_PROPERTY = "sun.security.smartcardio.library";
  private static final String LIBRARY_PATH_PROPERTY = "java.library.path";
  private static final String GNULINUX_OS_PROPERTY_PREFIX = "Linux";
  private static final String PCSC_LIBRARY_NAME = "pcsclite";
  private static final String UBUNTU_MULTILIB_32_SUFFIX = "i386-linux-gnu";
  private static final String UBUNTU_MULTILIB_64_SUFFIX = "x86_64-linux-gnu";
  private static final String JRE_BITNESS_PROPERTY = "os.arch";
  private static final String OS_NAME_PROPERTY = "os.name";
  private static final String JRE_BITNESS_32_VALUE = "i386";
  private static final String JRE_BITNESS_64_VALUE = "amd64";

  private enum UbuntuBitness {
    NA, PURE32, PURE64, MULTILIB
  }

  private LibJ2PCSCGNULinuxFix() {
  }

  /**
   * Make sure libpcsclite is found. The libj2pcsc.so from the JRE attempts to
   * dlopen using the linker name "libpcsclite.so" instead of the appropriate
   * "libpcsclite.so.1". This causes libpcsclite not to be found on GNU/Linux
   * distributions that don't have the libpcsclite.so symbolic link. This
   * method finds the library and forces the JRE to use it instead of
   * attempting to locate it by itself. See also:
   * http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=529339
   * <br>
   * Does nothing if not on a GNU/Linux system
   */
  static void fixNativeLibrary() {
    String osName = System.getProperty(OS_NAME_PROPERTY);
    if (osName != null && osName.startsWith(GNULINUX_OS_PROPERTY_PREFIX)) {
      LOGGER.info("OS is [" + osName + "]. Enabling PCSC library fix.");
      File libPcscLite = findGNULinuxNativeLibrary(PCSC_LIBRARY_NAME, PCSC_LIBRARY_VERSION);
      if (libPcscLite != null) {
        LOGGER.info("Setting [" + SMARTCARDIO_LIBRARY_PROPERTY + "] to [" + libPcscLite.getAbsolutePath() + "]");
        System.setProperty(SMARTCARDIO_LIBRARY_PROPERTY, libPcscLite.getAbsolutePath());
      }
    } else {
      LOGGER.info("OS is [" + osName + "]. Not Enabling PCSC library fix.");
    }
  }

  /*
   * Determine Ubuntu-type multilib configuration
   */
  private static UbuntuBitness getUbuntuBitness() {
    File multiLibDir32 = new File("/lib/" + UBUNTU_MULTILIB_32_SUFFIX);
    boolean has32 = multiLibDir32.exists() && multiLibDir32.isDirectory();
    File multiLibDir64 = new File("/lib/" + UBUNTU_MULTILIB_64_SUFFIX);
    boolean has64 = multiLibDir64.exists() && multiLibDir64.isDirectory();

    if (has32) {
      if (!has64) return UbuntuBitness.PURE32;
      return UbuntuBitness.MULTILIB;
    } else {
      if (has64) return UbuntuBitness.PURE64;
      return UbuntuBitness.NA;
    }
  }

  /*
   * Return the path with extension appended, if it wasn't already contained
   * in the path
   */
  private static String extendLibraryPath(String libPath, String extension) {
    return libPath.contains(extension) ? libPath : libPath + ":" + extension;
  }

  private static String addMultiarchPath(String libPath, String suffix) {
    String retval = extendLibraryPath(libPath, "/lib/" + suffix);
    return extendLibraryPath(retval, "/usr/lib/" + suffix);
  }

  /*
   * Oracle Java 7, java.library.path is severely limited as compared to the
   * OpenJDK default and doesn't contain Ubuntu 12's MULTILIB directories.
   * Test for Ubuntu in various configs and add the required paths
   */
  private static String fixPathForUbuntuMultiLib(String libraryPath) {
    LOGGER.info("Looking for Debian/Ubuntu-style multilib installation.");

    switch (getUbuntuBitness()) {
      case PURE32:
        // Pure 32-bit Ubuntu. Add the 32-bit lib dir.
        LOGGER.info("pure 32-bit Debian/Ubuntu detected, adding library paths containing 32-bit multilib suffix: " + UBUNTU_MULTILIB_32_SUFFIX);
        return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_32_SUFFIX);

      case PURE64:
        // Pure 64-bit Ubuntu. Add the 64-bit lib dir.
        LOGGER.info("pure 64-bit Debian/Ubuntu detected, adding library paths containing 64-bit multilib suffix: " + UBUNTU_MULTILIB_64_SUFFIX);
        return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_64_SUFFIX);

      case MULTILIB:
        // Multilib Ubuntu. Let the currently running JRE's bitness determine which lib dir to add.
        LOGGER.info("Multilib Ubuntu detected. Using JRE Bitness.");

        String jvmBinaryArch = System.getProperty(JRE_BITNESS_PROPERTY);
        if (jvmBinaryArch == null) {
          return libraryPath;
        }

        LOGGER.info("JRE Bitness is [" + jvmBinaryArch + "]");
        if (jvmBinaryArch.equals(JRE_BITNESS_32_VALUE)) {
          LOGGER.info("32-bit JRE, using 32-bit multilib suffix: " + UBUNTU_MULTILIB_32_SUFFIX);
          return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_32_SUFFIX);
        }

        if (jvmBinaryArch.equals(JRE_BITNESS_64_VALUE)) {
          LOGGER.info("64-bit JRE, using 64-bit multilib suffix: " + UBUNTU_MULTILIB_64_SUFFIX);
          return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_64_SUFFIX);
        }

        break;
    }

    LOGGER.info("Did not find Debian/Ubuntu-style multilib.");
    return libraryPath;
  }

  /*
   * Finds .so.version file on GNU/Linux. avoid guessing all GNU/Linux
   * distros' library path configurations on 32 and 64-bit when working around
   * the buggy libj2pcsc.so implementation based on JRE implementations adding
   * the native library paths to the end of java.library.path. Fixes the path
   * for Oracle JRE which doesn't contain the Ubuntu MULTILIB directories
   */
  private static File findGNULinuxNativeLibrary(String baseName, int version) {
    // get java.library.path
    String nativeLibraryPaths = System.getProperty(LIBRARY_PATH_PROPERTY);
    if (nativeLibraryPaths == null) {
      return null;
    }

    LOGGER.info("Original Path=[" + nativeLibraryPaths + "]");

    // when on Ubuntu, add appropriate MULTILIB path
    nativeLibraryPaths = fixPathForUbuntuMultiLib(nativeLibraryPaths);
    LOGGER.info("Path after Ubuntu multilib Fixes=[" + nativeLibraryPaths + "]");

    // scan the directories in the path and return the first library called "baseName" with version "version"
    String libFileName = System.mapLibraryName(baseName) + "." + version;
    LOGGER.info("Scanning path for [" + libFileName + "]");

    for (String nativeLibraryPath : nativeLibraryPaths.split(":")) {
      LOGGER.info("Scanning [" + nativeLibraryPath + "]");
      File libraryFile = new File(nativeLibraryPath, libFileName);
      if (libraryFile.exists()) {
        LOGGER.info("[" + libFileName + "] found in [" + nativeLibraryPath + "]");
        return libraryFile;
      }
    }

    LOGGER.info("[" + libFileName + "] not found.");
    return null;
  }
}
