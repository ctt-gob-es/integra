package es.gob.afirma.mreport.logger;

import org.apache.logging.log4j.LogManager;

public class Logger {
	
    /**
     * Attribute that represents the object that manages the log of the class.
     */
    private static org.apache.logging.log4j.Logger LOGGER;
	
    public Logger(String name) {
		
	LOGGER = LogManager.getLogger(name);
    }
	
    public Logger(Class<?> clazz) {
		
	LOGGER = LogManager.getLogger(clazz);
    }
	
    public static Logger getLogger(String name) {
				
	return new Logger(name);
    }
	
    public static Logger getLogger(Class<?> clazz) {
		
	return new Logger(clazz);
    }
	
    public void info(final Object message) {
		
	LOGGER.info(message);
    }
   
    public void info(final Object message, final Throwable t) {
    	
    	LOGGER.info(message, t);
    }
	
    public void debug(final Object message) {
    	
    	LOGGER.debug(message);
    }
   
    public void debug(final Object message, final Throwable t) {
    	
    	LOGGER.debug(message, t);
    }
    
    public void warn(final Object message) {
    	
    	LOGGER.warn(message);
    }
   
    public void warn(final Object message, final Throwable t) {
    	
    	LOGGER.warn(message, t);
    }
   
    public void error(final Object message) {
    	
    	LOGGER.error(message);
    }
    
    public void error(final Object message, final Throwable t) {
    	
    	LOGGER.error(message, t);
    } 

}
