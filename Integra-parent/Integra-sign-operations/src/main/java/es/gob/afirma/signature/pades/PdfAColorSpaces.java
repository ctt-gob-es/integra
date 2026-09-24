package es.gob.afirma.signature.pades;

import java.awt.color.ICC_Profile;
import java.io.IOException;
import java.util.Arrays;

import com.lowagie.text.pdf.PRStream;
import com.lowagie.text.pdf.PdfArray;
import com.lowagie.text.pdf.PdfBoolean;
import com.lowagie.text.pdf.PdfDictionary;
import com.lowagie.text.pdf.PdfICCBased;
import com.lowagie.text.pdf.PdfName;
import com.lowagie.text.pdf.PdfNumber;
import com.lowagie.text.pdf.PdfObject;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfStream;
import com.lowagie.text.pdf.PdfString;
import com.lowagie.text.pdf.PdfWriter;

/** Espacios de color independientes del dispositivo para apariencias PDF/A. */
final class PdfAColorSpaces {

    private PdfAColorSpaces() {
        // No instanciable
    }

    /**
     * Configura los espacios predeterminados usados por las apariencias PDF/A.
     * @param writer Escritor PDF que generara la apariencia.
     */
    static void configure(final PdfWriter writer) {
        if (writer == null) {
            throw new IllegalArgumentException("El escritor PDF no puede ser nulo"); //$NON-NLS-1$
        }

        writer.setDefaultColorspace(PdfName.DEFAULTGRAY, createCalGray());
        writer.setDefaultColorspace(PdfName.DEFAULTRGB, createCalRgb());
    }

    /**
     * Configura los espacios predeterminados reutilizando los espacios compatibles
     * del documento de entrada cuando todas las paginas son coherentes.
     * @param writer Escritor PDF que generara la apariencia.
     * @param reader Lector del PDF de entrada cuyos espacios se pueden reutilizar.
     */
    static void configure(final PdfWriter writer, final PdfReader reader) {
        if (writer == null) {
            throw new IllegalArgumentException("El escritor PDF no puede ser nulo"); //$NON-NLS-1$
        }
        if (reader == null) {
            throw new IllegalArgumentException("El lector PDF no puede ser nulo"); //$NON-NLS-1$
        }

        final PdfObject gray = getColorSpace(writer, reader, PdfName.DEFAULTGRAY, 1);
        final PdfObject rgb = getColorSpace(writer, reader, PdfName.DEFAULTRGB, 3);

        writer.setDefaultColorspace(PdfName.DEFAULTGRAY, gray != null ? gray : createCalGray());
        writer.setDefaultColorspace(PdfName.DEFAULTRGB, rgb != null ? rgb : createCalRgb());
    }

    private static PdfObject getColorSpace(final PdfWriter writer,
                                           final PdfReader reader,
                                           final PdfName defaultColorSpace,
                                           final int numberOfComponents) {
        final PdfObject existing = findCommonColorSpace(reader, defaultColorSpace, numberOfComponents);
        if (existing == null) {
            return null;
        }

        final PdfObject resolved = PdfReader.getPdfObject(existing);
        final PdfName colorSpaceType = getColorSpaceType(resolved);
        if (PdfName.ICCBASED.equals(colorSpaceType)) {
            try {
                return importIccColorSpace(writer, (PdfArray) resolved);
            }
            catch (final IOException | IllegalArgumentException e) {
                return null;
            }
        }
        return copyPdfObject(resolved);
    }

    private static PdfObject findCommonColorSpace(final PdfReader reader,
                                                  final PdfName defaultColorSpace,
                                                  final int numberOfComponents) {
        PdfObject selected = null;

        for (int pageNumber = 1; pageNumber <= reader.getNumberOfPages(); pageNumber++) {
            final PdfDictionary page = reader.getPageN(pageNumber);
            final PdfDictionary resources = getDictionary(page, PdfName.RESOURCES);
            final PdfDictionary colorSpaces = getDictionary(resources, PdfName.COLORSPACE);
            final PdfObject candidate = colorSpaces != null
                    ? PdfReader.getPdfObject(colorSpaces.get(defaultColorSpace))
                    : null;

            if (candidate == null) {
                continue;
            }
            if (!isCompatibleColorSpace(candidate, numberOfComponents)) {
                return null;
            }
            if (selected == null) {
                selected = candidate;
            }
            else if (!areEquivalentColorSpaces(selected, candidate)) {
                return null;
            }
        }

        return selected;
    }

    private static boolean isCompatibleColorSpace(final PdfObject colorSpace,
                                                  final int numberOfComponents) {
        final PdfName type = getColorSpaceType(colorSpace);
        if (PdfName.CALGRAY.equals(type)) {
            return numberOfComponents == 1;
        }
        if (PdfName.CALRGB.equals(type)) {
            return numberOfComponents == 3;
        }
        if (!PdfName.ICCBASED.equals(type) || !(colorSpace instanceof PdfArray)) {
            return false;
        }

        final PdfObject profileObject = getArrayObject((PdfArray) colorSpace, 1);
        final PdfDictionary profile = profileObject instanceof PdfDictionary
                ? (PdfDictionary) profileObject
                : null;
        final PdfObject components = profile != null
                ? PdfReader.getPdfObject(profile.get(PdfName.N))
                : null;
        return components instanceof PdfNumber
                && ((PdfNumber) components).intValue() == numberOfComponents;
    }

    private static boolean areEquivalentColorSpaces(final PdfObject first,
                                                     final PdfObject second) {
        final PdfName firstType = getColorSpaceType(first);
        final PdfName secondType = getColorSpaceType(second);
        if (firstType == null || !firstType.equals(secondType)) {
            return false;
        }
        if (PdfName.ICCBASED.equals(firstType)) {
            try {
                final PdfStream firstProfile = getIccProfile(first);
                final PdfStream secondProfile = getIccProfile(second);
                return firstProfile instanceof PRStream
                        && secondProfile instanceof PRStream
                        && Arrays.equals(
                                PdfReader.getStreamBytes((PRStream) firstProfile),
                                PdfReader.getStreamBytes((PRStream) secondProfile)
                        );
            }
            catch (final IOException e) {
                return false;
            }
        }
        return copyPdfObject(first).toString().equals(copyPdfObject(second).toString());
    }

    private static PdfObject importIccColorSpace(final PdfWriter writer,
                                                 final PdfArray colorSpace)
            throws IOException {
        final PdfStream profile = getIccProfile(colorSpace);
        if (!(profile instanceof PRStream)) {
            return null;
        }
        final ICC_Profile iccProfile = ICC_Profile.getInstance(
                PdfReader.getStreamBytes((PRStream) profile)
        );
        final PdfICCBased importedProfile = new PdfICCBased(
                iccProfile,
                writer.getCompressionLevel()
        );
        final PdfArray importedColorSpace = new PdfArray(PdfName.ICCBASED);
        importedColorSpace.add(writer.addToBody(importedProfile).getIndirectReference());
        return importedColorSpace;
    }

    private static PdfStream getIccProfile(final PdfObject colorSpace) {
        if (!(colorSpace instanceof PdfArray)) {
            return null;
        }
        final PdfObject profileObject = getArrayObject((PdfArray) colorSpace, 1);
        return profileObject instanceof PdfStream ? (PdfStream) profileObject : null;
    }

    private static PdfName getColorSpaceType(final PdfObject colorSpace) {
        if (!(colorSpace instanceof PdfArray)) {
            return null;
        }
        final PdfObject type = getArrayObject((PdfArray) colorSpace, 0);
        return type instanceof PdfName ? (PdfName) type : null;
    }

    private static PdfObject getArrayObject(final PdfArray array, final int index) {
        return index < array.size() ? PdfReader.getPdfObject(array.getPdfObject(index)) : null;
    }

    private static PdfDictionary getDictionary(final PdfDictionary dictionary, final PdfName key) {
        if (dictionary == null) {
            return null;
        }
        final PdfObject value = PdfReader.getPdfObject(dictionary.get(key));
        return value instanceof PdfDictionary ? (PdfDictionary) value : null;
    }

    private static PdfObject copyPdfObject(final PdfObject source) {
        final PdfObject resolved = PdfReader.getPdfObject(source);
        if (resolved instanceof PdfArray) {
            final PdfArray copy = new PdfArray();
            for (int i = 0; i < ((PdfArray) resolved).size(); i++) {
                copy.add(copyPdfObject(((PdfArray) resolved).getPdfObject(i)));
            }
            return copy;
        }
        if (resolved instanceof PdfDictionary) {
            final PdfDictionary copy = new PdfDictionary();
            for (final PdfName key : ((PdfDictionary) resolved).getKeys()) {
                copy.put(key, copyPdfObject(((PdfDictionary) resolved).get(key)));
            }
            return copy;
        }
        if (resolved instanceof PdfNumber) {
            return new PdfNumber(((PdfNumber) resolved).doubleValue());
        }
        if (resolved instanceof PdfBoolean) {
            return new PdfBoolean(((PdfBoolean) resolved).booleanValue());
        }
        if (resolved instanceof PdfString) {
            return new PdfString(((PdfString) resolved).getBytes());
        }
        return resolved;
    }

    private static PdfArray createCalGray() {
        final PdfDictionary parameters = new PdfDictionary();
        parameters.put(
                PdfName.WHITEPOINT,
                new PdfArray(new float[] { 0.9505f, 1f, 1.089f })
        );
        parameters.put(PdfName.GAMMA, new PdfNumber(2.2f));

        final PdfArray colorSpace = new PdfArray(PdfName.CALGRAY);
        colorSpace.add(parameters);
        return colorSpace;
    }

    private static PdfArray createCalRgb() {
        final PdfDictionary parameters = new PdfDictionary();
        parameters.put(
                PdfName.WHITEPOINT,
                new PdfArray(new float[] { 0.9505f, 1f, 1.089f })
        );
        parameters.put(
                PdfName.GAMMA,
                new PdfArray(new float[] { 2.2f, 2.2f, 2.2f })
        );
        parameters.put(
                PdfName.MATRIX,
                new PdfArray(new float[] {
                        0.4124f, 0.3576f, 0.1805f,
                        0.2126f, 0.7152f, 0.0722f,
                        0.0193f, 0.1192f, 0.9505f
                })
        );

        final PdfArray colorSpace = new PdfArray(PdfName.CALRGB);
        colorSpace.add(parameters);
        return colorSpace;
    }
}