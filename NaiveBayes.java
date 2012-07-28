/* 
 * @author: Ayon Chakraborty
 * @course project: Network Security
 * @school: SUNY Stony Brook 
 *
 */
 
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;



class Word {
	private String word;    // The String itself
	private int countBad;   // The total times it appears in "bad" messages 
	private int countGood;  // The total times it appears in "good" messages
	private float rBad;     // bad count / total bad words
	private float rGood;    // good count / total good words
	private float pSpam;    // probability this word is Spam

	// Create a word, initialize all vars to 0
	public Word(String s) {
		word = s;
		countBad = 0;
		countGood = 0;
		rBad = 0.0f;
		rGood = 0.0f;
		pSpam = 0.0f;
	}

	// Increment bad counter
	public void countBad() {
		countBad++;
	}

	// Increment good counter
	public void countGood() {
		countGood++;
	}

	// Computer how often this word is bad
	public void calcBadProb(int total) {
		if (total > 0) rBad = countBad / (float) total;
	}

	// Computer how often this word is good
	public void calcGoodProb(int total) {
		//if (total > 0) rGood = 2*countGood / (float) total;
		if (total > 0) rGood = countGood / (float) total;
	}

	// Implement bayes rules to computer how likely this word is "spam"
	public void finalProbability() {
		if (rGood + rBad > 0) pSpam = rBad / (rBad + rGood);
		if (pSpam < 0.01f) pSpam = 0.01f;
		else if (pSpam > 0.99f) pSpam = 0.99f;
	}


	// The "interesting" rating for a word is
	// How different from 0.5 it is
	public float interesting() {
		return Math.abs(0.5f  - pSpam);
	}

	// Some getters and setters	
	public float getPGood() {
		return rGood;
	}

	public float getPBad() {
		return rBad;
	}

	public float getPSpam() {
		return pSpam;
	}

	public void setPSpam(float f) {
		pSpam = f;
	}

	public String getWord() {
		return word;
	}

}



public class NaiveBayes {
	static HashMap words;
	// How to split the String into  tokens
	static String splitregex;
	// Regex to eliminate junk (although we really should welcome the junk)
	static Pattern wordregex;
	static int limit = 0;
	
	public void trainOnData() {

		// Train spam with a file of spam e-mails

		words = new HashMap();
		splitregex = "\\W";
		wordregex = Pattern.compile("\\w+");
		try{
		trainSpam("spammails.txt");
		// Train spam with a file of regular e-mails

		trainGood("goodmails.txt");

		finalizeTraining();
	
		}catch (Exception e) {
			// TODO: handle exception
		}
		
	}
	public void train() {
		words = new HashMap();
		splitregex = "\\W";
		wordregex = Pattern.compile("\\w+");
		try {

			// Train spam with a file of spam e-mails

			trainSpam("spammails.txt");
			// Train spam with a file of regular e-mails

			trainGood("goodmails.txt");

			finalizeTraining();

			

			String pfolder="C:\\Users\\sundi133\\Downloads\\netsecproj\\validated";
			//C:\Users\sundi133\Downloads\netsecproj\Japanese
			File folder = new File(pfolder);
			File[] listOfFiles = folder.listFiles();
			FileWriter writer=null;

			
			for (int i = 0; i < listOfFiles.length ; i++) {
				try {

					String currentfile = listOfFiles[i].getName().substring(0, listOfFiles[i].getName().length()-4) ;
					File fXmlFile = new File(pfolder+"\\"+currentfile +".xml");
					File outxml=new File("C:\\Users\\sundi133\\workspace\\TWEET\\parsedeval\\"+currentfile +"_out.xml");
					writer=new FileWriter(outxml);
					writer.write("<root>\n");
					int ctr=0;
					DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
					DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
					Document doc = dBuilder.parse(fXmlFile);
					doc.getDocumentElement().normalize();
				
					String[] tag = {"id","name","screen_name","followers_count","friends_count","profile_image_url","description","created_at","listed_count","favourites_count","statuses_count","tweet_count","default_profile",
							"default_profile_image","profile_background_image_url","profile_background_image_url_https","profile_background_tile","profile_use_background_image",
							"profile_background_tile","notifications","location","tweet"};
					for(int n=0;n<tag.length;n++){
						NodeList id = doc.getElementsByTagName(tag[n]);
						id.getLength();
						if (id.item(0) instanceof Element) {
							Element root = (Element)id.item(0);
							if(root.getNodeName().indexOf("tweet")==-1){
								//System.out.println("sundi 2 " +  root.getNodeName());
								if(root.getNodeName().indexOf("description")==-1)
									writer.write("<" + root.getNodeName()+">" + root.getTextContent()+"</" + root.getNodeName()+">\n" );
								else{
									if(root.getTextContent().trim()=="" || root.getTextContent().trim()==null){
										writer.write("<" + root.getNodeName()+">" + 0.5+"</" + root.getNodeName()+">\n" );
									}else{
										if(analyze(root.getTextContent()))
											writer.write("<" + root.getNodeName()+">" + 1+"</" + root.getNodeName()+">\n" );
										else
											writer.write("<" + root.getNodeName()+">" + 0+"</" + root.getNodeName()+">\n" );
									}
									
									
								}
									
							}
							else
							{
								writer.write("<tweets>\n");
								NodeList nl = doc.getElementsByTagName("tweet");

								if(nl != null && nl.getLength() > 0) {
									for(int j = 0 ; j < nl.getLength();j++) {

										//get the employee element
										writer.write("<tweet>\n");
										Element el = (Element)nl.item(j);
										String node="text";
										String val = getTextValue(el,node);
										writer.write("<" +node +">" + val+"</" + node+">\n" );

										//String created_at = getTextValue(el,"created_at");
										node="created_at";
										val = getTextValue(el,node);
										writer.write("<" +node +">" + val+"</" + node+">\n" );

										//String in_reply_to_status_id = getTextValue(el,"in_reply_to_status_id");
										node="in_reply_to_status_id";
										val = getTextValue(el,node);
										writer.write("<" +node +">" + val+"</" + node+">\n" );

										//String in_reply_to_user_id = getTextValue(el,"in_reply_to_user_id");
										node="in_reply_to_user_id";
										val = getTextValue(el,node);
										writer.write("<" +node +">" + val+"</" + node+">\n" );

										//String in_reply_to_screen_name = getTextValue(el,"in_reply_to_screen_name");
										node="in_reply_to_screen_name";
										val = getTextValue(el,node);
										writer.write("<" +node +">" + val+"</" + node+">\n" );

										//String retweet_count = getTextValue(el,"retweet_count");
										node="retweet_count";
										val = getTextValue(el,node);
										writer.write("<" +node +">" + val+"</" + node+">\n" );


										node="retweeted";
										val = getTextValue(el,node);
										writer.write("<" +node +">" + val+"</" + node+">\n" );
										
										writer.write("</tweet>\n");

									}
								}
								writer.write("</tweets>\n");
							}
							//System.out.println("<" + root.getNodeName()+">" + root.getTextContent()+"</" + root.getNodeName()+">\n" );

						}else{
							//System.out.println("sundi ");
							
						}

					}
					writer.write("</root>\n");
					writer.close();
				} catch (Exception e) {
					e.printStackTrace();
				}


			}


		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static String getTextValue(Element ele, String tagName) {
		// TODO Auto-generated method stub
		String textVal = null;
		NodeList nl = ele.getElementsByTagName(tagName);
		if(nl != null && nl.getLength() > 0) {
			Element el = (Element)nl.item(0);
			try{
			textVal = el.getFirstChild().getNodeValue();
			}catch (Exception e) {
				// TODO: handle exception
			}
		}

		return textVal;
	}

	public static String readContent1(String filename ) throws IOException {
		// Create an input stream and file channel
		// Using first arguemnt as file name to read in
		FileInputStream fis = new FileInputStream(filename);
		FileChannel fc = fis.getChannel();

		// Read the contents of a file into a ByteBuffer
		ByteBuffer bb = ByteBuffer.allocate((int)fc.size());
		fc.read(bb);
		fc.close();

		// Convert ByteBuffer to one long String
		String content = new String(bb.array());
		return content;
	}

	public static void trainSpam(String file) throws IOException {
		//A2ZFileReader fr = new A2ZFileReader(file);


		String content = readContent1(file);
		String[] tokens = content.split(splitregex);
		int spamTotal = 0;//tokenizer.countTokens(); // How many words total

		// For every word token
		for (int i = 0; i < tokens.length; i++) {
			String word = tokens[i].toLowerCase();
			Matcher m = wordregex.matcher(word);
			if (m.matches()) {
				spamTotal++;
				// If it exists in the HashMap already
				// Increment the count
				if (words.containsKey(word)) {
					Word w = (Word) words.get(word);
					w.countBad();
					// Otherwise it's a new word so add it
				} else {
					Word w = new Word(word);
					w.countBad();
					words.put(word,w);
				}
			}
		}

		// Go through all the words and divide
		// by total words
		Iterator iterator = words.values().iterator();
		while (iterator.hasNext()) {
			Word word = (Word) iterator.next();
			word.calcBadProb(spamTotal);
		}
	}


	private String readContent(String file) throws IOException {
		limit =15;
		FileInputStream fis;
		try {
			fis = new FileInputStream(file);

			FileChannel fc = fis.getChannel();

			// Read the contents of a file into a ByteBuffer
			ByteBuffer bb = ByteBuffer.allocate((int)fc.size());
			fc.read(bb);
			fc.close();

			// Convert ByteBuffer to one long String
			String content = new String(bb.array());
			return content;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}


	//	 Receive a file that is marked as "Good"
	// Perhaps this should just receive a String
	public static void trainGood(String file) throws IOException {

		String content = readContent1(file);
		String[] tokens = content.split(splitregex);
		int goodTotal = 0;//tokenizer.countTokens(); // How many words total
		limit =15;
		// For every word token
		for (int i = 0; i < tokens.length; i++) {
			String word = tokens[i].toLowerCase();
			Matcher m = wordregex.matcher(word);
			if (m.matches()) {
				goodTotal++;
				// If it exists in the HashMap already
				// Increment the count
				if (words.containsKey(word)) {
					Word w = (Word) words.get(word);
					w.countGood();
					// Otherwise it's a new word so add it
				} else {
					Word w = new Word(word);
					w.countGood();
					words.put(word,w);
				}
			}
		}

		// Go through all the words and divide
		// by total words
		Iterator iterator = words.values().iterator();
		while (iterator.hasNext()) {
			Word word = (Word) iterator.next();
			word.calcGoodProb(goodTotal);
		}
	}



	public int analyseData(String mail) {
		// TODO Auto-generated method stub
		if(mail==null || mail.trim().equalsIgnoreCase("")){
			return 0;//none
		}
		if(analyze(mail)){
			return 2;//spam
		}
		return 1;

	}

	public static boolean analyze(String mail) {

		int count=0;
		String[]chkfakedesc =mail.split(" ");
		for(int k=0;k<chkfakedesc.length;k++){
			if(chkfakedesc[k].startsWith("#")){
				count++;
			}
		}
		if(count>=chkfakedesc.length/4)
			return true;//spam
		// Create an arraylist of 15 most "interesting" words
		// Words are most interesting based on how different their Spam probability is from 0.5
		ArrayList interesting = new ArrayList();

		// For every word in the String to be analyzed
		String[] tokens = mail.split(splitregex);

		for (int i = 0; i < tokens.length; i++) {
			String s = tokens[i].toLowerCase();
			Matcher m = wordregex.matcher(s);
			if (m.matches()) {

				Word w;

				// If the String is in our HashMap get the word out
				if (words.containsKey(s)) {
					w = (Word) words.get(s);
					// Otherwise, make a new word with a Spam probability of 0.4;
				} else {
					w = new Word(s);
					w.setPSpam(0.4f);
				}



				// If this list is empty, then add this word in!
				if (interesting.isEmpty()) {
					interesting.add(w);
					// Otherwise, add it in sorted order by interesting level
				} else {
					for (int j = 0; j < interesting.size(); j++) {
						// For every word in the list already
						Word nw = (Word) interesting.get(j);
						// If it's the same word, don't bother
						if (w.getWord().equals(nw.getWord())) {
							break;
							// If it's more interesting stick it in the list
						} else if (w.interesting() > nw.interesting()) {
							interesting.add(j,w);
							break;
							// If we get to the end, just tack it on there
						} else if (j == interesting.size()-1) {
							interesting.add(w);
						}
					}
				}

				// If the list is bigger than the limit, delete entries
				// at the end (the more "interesting" ones are at the 
				// start of the list
				while (interesting.size() > limit) interesting.remove(interesting.size()-1);

			}
		}

		// Apply Bayes' rule 
		float pposproduct = 1.0f;
		float pnegproduct = 1.0f;
		// For every word, multiply Spam probabilities ("Pspam") together
		// (As well as 1 - Pspam)
		for (int i = 0; i < interesting.size(); i++) {
			Word w = (Word) interesting.get(i);
			//System.out.println(w.getWord() + " " + w.getPSpam());
			pposproduct *= w.getPSpam();
			pnegproduct *= (1.0f - w.getPSpam());
		}

		// Apply formula
		float pspam = pposproduct / (pposproduct + pnegproduct);


		// If the computed value is great than 0.9 we have a Spam!!
		if (pspam > 0.9f){
			//System.out.println("\nSpam rating: " + pspam);
			return true;
		}
		else {
			//System.out.println("\nHam rating: " + pspam);
			return false;
		}

	}

	// Display info about the words in the HashMap
	public void displayStats() {
		Iterator iterator = words.keySet().iterator();
		while (iterator.hasNext()) {
			String key = (String) iterator.next();
			Word word = (Word) words.get(key);
			if (word != null) {
				//System.out.println(key + " pBad: " + word.getPBad() + " pGood: " + word.getPGood() + " pSpam: " + word.getPSpam());
				//System.out.println(key + " " + word.getPSpam());
			}
		}		
	}


	// For every word, calculate the Spam probability
	public static void finalizeTraining() {

		Iterator iterator = words.values().iterator();
		while (iterator.hasNext()) {
			Word word = (Word) iterator.next();
			word.finalProbability();
		}	
	}

	private static String getTagValue(String sTag, Element eElement) {
		NodeList nlList = eElement.getElementsByTagName(sTag).item(0).getChildNodes();
		Node nValue = (Node) nlList.item(0);
		String ret="";
		if(nValue!=null) ret=nValue.getNodeValue();
		return ret;
	}

}