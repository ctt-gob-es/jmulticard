package es.gob.jmulticard.jse.smartcardio;

import java.io.File;
import java.util.logging.Logger;

/** Encapsulate fixes regarding the dynamic loading of the pcsclite library on
 * GNU/Linux Systems. Statically call LibJ2PCSCGNULinuxFix.fixNativeLibrary()
 * before using a TerminalFactory.
 * @author Frank Cornelis
 * @author Frank Marien. */
final class LibJ2PCSCGNULinuxFix {

	private static final int PCSC_LIBRARY_VERSION = 1;
	private static final String SMARTCARDIO_LIBRARY_PROPERTY = "sun.security.smartcardio.library"; //$NON-NLS-1$
	private static final String LIBRARY_PATH_PROPERTY = "java.library.path"; //$NON-NLS-1$
	private static final String GNULINUX_OS_PROPERTY_PREFIX = "Linux"; //$NON-NLS-1$
	private static final String PCSC_LIBRARY_NAME = "pcsclite"; //$NON-NLS-1$
	private static final String UBUNTU_MULTILIB_32_SUFFIX = "i386-linux-gnu"; //$NON-NLS-1$
	private static final String UBUNTU_MULTILIB_64_SUFFIX = "x86_64-linux-gnu"; //$NON-NLS-1$
	private static final String JRE_BITNESS_PROPERTY = "os.arch"; //$NON-NLS-1$
	private static final String OS_NAME_PROPERTY = "os.name"; //$NON-NLS-1$
	private static final String JRE_BITNESS_32_VALUE = "i386"; //$NON-NLS-1$
	private static final String JRE_BITNESS_64_VALUE = "amd64"; //$NON-NLS-1$

	private static final String LIBDIR = "/lib/"; //$NON-NLS-1$

	private enum UbuntuBitness {
		NA, PURE32, PURE64, MULTILIB
	}

	private LibJ2PCSCGNULinuxFix() {
		// No instanciable
	}

	/** Make sure libpcsclite is found. The libj2pcsc.so from the JRE attempts to
	 * dlopen using the linker name "libpcsclite.so" instead of the appropriate
	 * "libpcsclite.so.1". This causes libpcsclite not to be found on GNU/Linux
	 * distributions that don't have the libpcsclite.so symbolic link. This method
	 * finds the library and forces the JRE to use it instead of attempting to
	 * locate it by itself. See also: <a href=
	 * "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=529339">http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=529339</a>
	 * <br>
	 * Does nothing if not on a GNU/Linux system. */
	static void fixNativeLibrary() {
		final String osName = System.getProperty(OS_NAME_PROPERTY);
		if (osName != null && osName.startsWith(GNULINUX_OS_PROPERTY_PREFIX)) {
			final File libPcscLite = findGNULinuxNativeLibrary(PCSC_LIBRARY_NAME, PCSC_LIBRARY_VERSION);
			if (libPcscLite != null) {
				System.setProperty(SMARTCARDIO_LIBRARY_PROPERTY, libPcscLite.getAbsolutePath());
			}
		}
	}

	/** Determine Ubuntu-type multilib configuration. */
	private static UbuntuBitness getUbuntuBitness() {
		final File multiLibDir32 = new File(LIBDIR + UBUNTU_MULTILIB_32_SUFFIX);
		final boolean has32 = multiLibDir32.exists() && multiLibDir32.isDirectory();
		final File multiLibDir64 = new File(LIBDIR + UBUNTU_MULTILIB_64_SUFFIX);
		final boolean has64 = multiLibDir64.exists() && multiLibDir64.isDirectory();

		if (has32) {
			if (!has64) {
				return UbuntuBitness.PURE32;
			}
			return UbuntuBitness.MULTILIB;
		}
		if (has64) {
			return UbuntuBitness.PURE64;
		}
		return UbuntuBitness.NA;
	}

	/** Return the path with extension appended, if it wasn't already contained in
	 * the path. */
	private static String extendLibraryPath(final String libPath, final String extension) {
		return libPath.contains(extension) ? libPath : libPath + ":" + extension; //$NON-NLS-1$
	}

	private static String addMultiarchPath(final String libPath, final String suffix) {
		final String retval = extendLibraryPath(libPath, LIBDIR + suffix);
		return extendLibraryPath(retval, "/usr" + LIBDIR + suffix); //$NON-NLS-1$
	}

	/** Oracle Java 7, <code>java&#46;library&#46;path</code> is severely limited as compared to the
	 * OpenJDK default and doesn't contain Ubuntu 12's MULTILIB directories. Test
	 * for Ubuntu in various configs and add the required paths. */
	private static String fixPathForUbuntuMultiLib(final String libraryPath) {

		switch (getUbuntuBitness()) {
			case PURE32:
				// Pure 32-bit Ubuntu. Add the 32-bit lib dir.
				return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_32_SUFFIX);

			case PURE64:
				// Pure 64-bit Ubuntu. Add the 64-bit lib dir.
				return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_64_SUFFIX);

			case MULTILIB:
				// Multilib Ubuntu. Let the currently running JRE's bitness determine which lib
				// dir to add.
				final String jvmBinaryArch = System.getProperty(JRE_BITNESS_PROPERTY);
				if (jvmBinaryArch == null) {
					return libraryPath;
				}
				if (jvmBinaryArch.equals(JRE_BITNESS_32_VALUE)) {
					return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_32_SUFFIX);
				}
				if (jvmBinaryArch.equals(JRE_BITNESS_64_VALUE)) {
					return addMultiarchPath(libraryPath, UBUNTU_MULTILIB_64_SUFFIX);
				}
				break;

			default:
				Logger.getLogger("test.es.gob.jmulticard").warning( //$NON-NLS-1$
					"No se ha podido determinar la arquitectura de Ubuntu, no se aplicaran correcciones de directorio de biliotecas" //$NON-NLS-1$
				);
				break;
		}

		return libraryPath;
	}

	/** Finds <code>&#46;so&#46;version</code> file on GNU/Linux. avoid guessing all GNU/Linux distros'
	 * library path configurations on 32 and 64-bit when working around the buggy
	 * libj2pcsc.so implementation based on JRE implementations adding the native
	 * library paths to the end of java.library.path. Fixes the path for Oracle JRE
	 * which doesn't contain the Ubuntu MULTILIB directories. */
	private static File findGNULinuxNativeLibrary(final String baseName, final int version) {
		// get java.library.path
		String nativeLibraryPaths = System.getProperty(LIBRARY_PATH_PROPERTY);
		if (nativeLibraryPaths == null) {
			return null;
		}

		// when on Ubuntu, add appropriate MULTILIB path
		nativeLibraryPaths = fixPathForUbuntuMultiLib(nativeLibraryPaths);

		// scan the directories in the path and return the first library called
		// "baseName" with version "version"
		final String libFileName = System.mapLibraryName(baseName) + "." + version; //$NON-NLS-1$

		for (final String nativeLibraryPath : nativeLibraryPaths.split(":")) { //$NON-NLS-1$
			final File libraryFile = new File(nativeLibraryPath, libFileName);
			if (libraryFile.exists()) {
				return libraryFile;
			}
		}

		return null;
	}
}
