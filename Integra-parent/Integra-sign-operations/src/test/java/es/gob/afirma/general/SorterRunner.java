// Copyright (C) 2012-13 MINHAP, Gobierno de España
// This program is licensed and may be used, modified and redistributed under the terms
// of the European Public License (EUPL), either version 1.1 or (at your
// option) any later version as soon as they are approved by the European Commission.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and
// more details.
// You should have received a copy of the EUPL1.1 license
// along with this program; if not, you may find it at
// http://joinup.ec.europa.eu/software/page/eupl/licence-eupl

/**
 * <b>File:</b><p>es.gob.afirma.general.SorterRunner.java.</p>
 * <b>Description:</b><p>Class that allows to execute JUnit tests on alphabetical order.</p>
 * <b>Project:</b><p>Library for the integration with the services of @Firma, eVisor and TS@.</p>
 * <b>Date:</b><p>10/04/2015.</p>
 * @author Gobierno de España.
 * @version 1.0, 10/04/2015.
 */
package es.gob.afirma.general;

import java.util.Comparator;

import org.junit.runner.Description;
import org.junit.runner.manipulation.Sorter;
import org.junit.runners.model.InitializationError;

/**
 * <p>Class that allows to execute JUnit tests on alphabetical order.</p>
 * <b>Project:</b><p>@Firma and TS@ Web Services Integration Platform.</p>
 * @version 1.0, 10/04/2015.
 */
public class SorterRunner extends org.junit.runners.BlockJUnit4ClassRunner {

    /**
     * Constructor method for the class SorterRunner.java.
     * @param klass Parameter that represents the test class.
     * @throws InitializationError If the test class is malformed.
     */
    public SorterRunner(Class<?> klass) throws InitializationError {
	super(klass);
	sort(new Sorter(COMPARATOR));
    }

    /**
     * Constant attribute that represents a comparison function, which imposes a total ordering on some collection of objects.
     */
    private static final Comparator<Description> COMPARATOR = new Comparator<Description>() {

	/**
	 * Method that compares two tests.
	 * @param o1 Parameter that represents the first test name to compare.
	 * @param o2 Parameter that represents the second test name to compare.
	 * @return the value 0 if both names are equal; a value less than 0 if the first name is lexicographically less than the second name;
	 * and a value greater than 0 if the first name is lexicographically greater than the second name.
	 */
	public int compare(Description o1, Description o2) {
	    return o1.getDisplayName().compareTo(o2.getDisplayName());
	}
    };

}
