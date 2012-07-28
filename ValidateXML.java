import java.io.*;

/* if the generated XML file contains invalid characters remove them */

public class ValidateXML {
	
	public static File generateValidatedXML(File fn) throws IOException{
		System.out.println("Validate XML called: "+System.currentTimeMillis());
		String fileName = fn.getName();
        String outputFileName = fn.getParent()+fn.getName().substring(0, fn.getName().indexOf(".")-1)+"_validated.xml";
     
        /**
            * Create a reader to read the input file
            */
           BufferedReader in = new BufferedReader(new FileReader(fileName));
           String line = "";

           String formattedStr = "";
           int count = 0;
           /**
            * Iterate through each line of content
            * remove any non-ASCII characters with blank using
            * regular expression.
            *
            * Append the new line character properly.
            */
           while ((line = in.readLine()) != null) {
               if (count == 0)
                   formattedStr += line.replaceAll("&","");//formattedStr += line.replaceAll("[^\\p{ASCII}]", "").replaceAll("[,&*()^!$%]","");
               else
                   formattedStr += "\n" + line.replaceAll("&","");//formattedStr += "\n" + line.replaceAll("[^\\p{ASCII}]", "").replaceAll("[,&*()^!$%]","");

               count++;
           }

           /**
            * Write the content to the output file using BufferedWriter object.
            */
           FileWriter writer=new FileWriter(outputFileName);
           writer.write(formattedStr);

           /**
            * Once done, flush the writer and close it.
            */
           writer.flush();
           writer.close();

           return new File(outputFileName);
	}
 
    public static void main(String args[]) {
	
	    File folder = new File("E:/Network Security/Project/hamprofilesextracted");
	    File[] listOfFiles = folder.listFiles();
 
       
 
		for (int i = 0; i < listOfFiles.length ; i++) {
		
		System.out.println("Validating # "+i);
		
		
		 String currentfile = listOfFiles[i].getName().substring(0, listOfFiles[i].getName().length()-4) ;
		 String fileName = "E:/Network Security/Project/hamprofilesextracted/"+currentfile+".xml";
         String outputFileName = "E:/Network Security/Project/hamprofilesvalidated/"+currentfile+".xml";
      
    	  try {
 
            /**
             * Create a reader to read the input file
             */
            BufferedReader in = new BufferedReader(new FileReader(fileName));
            String line = "";
 
            String formattedStr = "";
            int count = 0;
            /**
             * Iterate through each line of content
             * remove any non-ASCII characters with blank using
             * regular expression.
             *
             * Append the new line character properly.
             */
            while ((line = in.readLine()) != null) {
                if (count == 0)
                    formattedStr += line.replaceAll("&","");//formattedStr += line.replaceAll("[^\\p{ASCII}]", "").replaceAll("[,&*()^!$%]","");
                else
                    formattedStr += "\n" + line.replaceAll("&","");//formattedStr += "\n" + line.replaceAll("[^\\p{ASCII}]", "").replaceAll("[,&*()^!$%]","");
 
                count++;
            }
 
            /**
             * Write the content to the output file using BufferedWriter object.
             */
            FileWriter writer=new FileWriter(outputFileName);
            writer.write(formattedStr);
 
            /**
             * Once done, flush the writer and close it.
             */
            writer.flush();
            writer.close();
 
        } catch (Exception e) {
            e.printStackTrace();
        }
		
		}
   

   }
}
 