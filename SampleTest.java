/* 
 * @author: Ayon Chakraborty
 * @course project: Network Security
 * @school: SUNY Stony Brook 
 *
 */
 
import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.text.DecimalFormat;
import java.util.Scanner;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import weka.classifiers.bayes.NaiveBayesUpdateable;
import weka.classifiers.functions.SMO;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ConverterUtils.DataSource;
import weka.filters.unsupervised.attribute.NumericToNominal;


public class SampleTest {

	/**
	 * @param args
	 * @throws IOException 
	 * @throws SAXException 
	 * @throws ParserConfigurationException 
	 */
	public static File generateValidatedUserXml(String sn) throws IOException, ParserConfigurationException, SAXException{
		
		String sn1path = TwitterProfileCrawler.generateRawXML(sn);
		File fn1=new File(sn1path);
		File fn1Compressed=ParseDataEx.compressXML(fn1);
		File fn1Validated=ValidateXML.generateValidatedXML(fn1Compressed);
		return fn1Validated;
		//return getTranslated(fn1Validated,sn);
	}

	private static File getTranslated(File fn1Validated, String user) {
		// TODO Auto-generated method stub
		FileWriter writer=null;
		File outxml=null;

		try{

			//File fXmlFile = new File(pfolder+"\\"+currentfile +".xml");
			//System.out.println(fn1Validated.getName().substring(fn1Validated.getName()));
			outxml=new File("demotranslated/" +user + "_out.xml");
			////System.out.println(currentfile);
			writer=new FileWriter(outxml);
			writer.write("<root>\n");
			int ctr=0;
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();


			Document doc = dBuilder.parse(fn1Validated.getName());
			doc.getDocumentElement().normalize();
			////System.out.println("Root element :" + doc.getDocumentElement().getNodeName());
			//get usr atrributes

			String fromlang="en";
			Node child = doc.getDocumentElement().getFirstChild();
			while(child!=null){
				try{
					if(child.getNodeName().trim().equalsIgnoreCase("tweets")){
						writer.write("<tweets>\n");
						NodeList tweets = doc.getElementsByTagName("tweet");
						for (int temp = 0; temp < tweets.getLength(); temp++) {
							Node nNode = tweets.item(temp);
							//String fromlang="en";
							if (nNode.getNodeType() == Node.ELEMENT_NODE) {
								Element eElement = (Element) nNode;
								writer.write("<tweet>\n");

								if(fromlang.equalsIgnoreCase("en")){
									writer.write("<text>"+getTagValue("text", eElement)+"</text>\n");
								}else {
									try{
									//	writer.write("<text>"+translate(getTagValue("text", eElement),fromlang)+"</text>\n");
										writer.write("<text>"+getTagValue("text", eElement)+"</text>\n");
									}catch (Exception e) {
										// TODO: handle exception
										writer.write("<text>"+getTagValue("text", eElement)+"</text>\n");
									}

								}

								writer.write("<created_at>"+getTagValue("created_at", eElement)+"</created_at>\n");
								writer.write("<in_reply_to_status_id>"+getTagValue("in_reply_to_status_id", eElement)+"</in_reply_to_status_id>\n");
								writer.write("<in_reply_to_user_id>"+getTagValue("in_reply_to_user_id", eElement)+"</in_reply_to_user_id>\n");
								writer.write("<in_reply_to_screen_name>"+getTagValue("in_reply_to_screen_name", eElement)+"</in_reply_to_screen_name>\n");
								writer.write("<retweet_count>"+getTagValue("retweet_count", eElement)+"</retweet_count>\n");
								writer.write("<retweeted>"+getTagValue("retweeted", eElement)+"</retweeted>\n");
								writer.write("</tweet>\n");

							}
						}
						writer.write("</tweets>\n");
					}else{

						if(child.getNodeName().equalsIgnoreCase("#text")){

						}else{
							if(child.getNodeName().equalsIgnoreCase("lang")){
								fromlang =  child.getTextContent();
							}

							if(child.getNodeName().equalsIgnoreCase("description") 
									||
									child.getNodeName().equalsIgnoreCase("name")
									||
									child.getNodeName().equalsIgnoreCase("screen_name")
							){
								if(!fromlang.equalsIgnoreCase("en")){
									try{
										writer.write("<" + child.getNodeName() +">" + translate(child.getTextContent(),fromlang) +"</" + child.getNodeName() +">\n");
									}catch (Exception e) {
										// TODO: handle exception
										writer.write("<" + child.getNodeName() +">" + child.getTextContent() +"</" + child.getNodeName() +">\n");
									}

								}
								else{
									writer.write("<" + child.getNodeName() +">" + child.getTextContent() +"</" + child.getNodeName() +">\n");
								}
							}
							else{
								writer.write("<" + child.getNodeName() +">" + child.getTextContent() +"</" + child.getNodeName() +">\n");
							}
							////System.out.println("<" + child.getNodeName() +">" + child.getTextContent() +"</" + child.getNodeName() +">\n\n");


						}

					}
				}catch (Exception e) {
					// TODO: handle exception
				}
				child=child.getNextSibling();
			}
		
			writer.write("</root>\n");
			writer.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return outxml;
	}

	public String analyse(String usera,String userb) {
		// TODO Auto-generated method stub
		//System.out.println("Analyze called: "+System.currentTimeMillis());

		deleteFile();
		String res="";

		try{
			Scanner in = new Scanner(System.in);
			System.out.println("user1 sending request to user2 : ");
			System.out.println("user1: ");
			String user1=usera;
			System.out.println("user2: ");
			String user2=userb;
			
			System.out.println("Analysing...");
			
			File f1=generateValidatedUserXml(user1);
			File f2=generateValidatedUserXml(user2);

			//System.out.println("NaiveByes spam called: "+System.currentTimeMillis());
			NaiveBayes nb = new NaiveBayes();
			nb.trainOnData();
			//System.out.println("NaiveByes spam done: "+System.currentTimeMillis());

			File dat=FeatureExtraction.generateDat(f1, nb);
			String trainDat="train_h221_s221.dat";
			DataSource source = new DataSource(trainDat);
			Instances train = source.getDataSet();
			NumericToNominal ntn=new NumericToNominal();
			ntn.setInputFormat(train);

			
			//System.out.println("Train called: "+System.currentTimeMillis());
			SMO classifier=Classifier.train(train,ntn);
			//System.out.println("Train Done: "+System.currentTimeMillis());
			
			source = new DataSource(dat.getAbsolutePath());
			Instances test = source.getDataSet();


			for (int i = 0; i < test.numInstances(); i++) {
				ntn.input(test.instance(i));
			}
			ntn.batchFinished();
			Instances newTestData = ntn.getOutputFormat();

			Instance processedTest;
			while ((processedTest = ntn.output()) != null) {
				newTestData.add(processedTest);
			}

			//classify
			System.out.println("Classify called: "+System.currentTimeMillis());
			double pred = classifier.classifyInstance(newTestData.instance(0));
			String classPredicted=newTestData.classAttribute().value((int) pred);
			System.out.println("Classify done: "+System.currentTimeMillis());

			//System.out.println();
				ScoreToReq scoretoreq = new ScoreToReq("demotranslated");
				double score = scoretoreq.getScore();
				if(classPredicted.equalsIgnoreCase("2")){
					//System.out.print("Suspicious measure : " + classPredicted);
					System.out.print("Suspicious Account!! ");
					res+="Suspicious Account!!      ";
				}else{
					//System.out.print("Suspicious measure : " + classPredicted);
					System.out.print("Normal Account :) ");
					res+="Normal Account , ";
				}
				
				//System.out.print(" Profile Similarity score : "+score);
				//DecimalFormat df = new DecimalFormat("#.####");
				//res+=" Simalirity : "+df.format(score);;
				//System.out.print(" : Rating : ");
				res+=" Recommended Rating :   ";
				if(score < 0.05){
					System.out.println("*");
					res+="*";
				}
				else if(score >= 0.05 && score < 0.25){
					System.out.println("**");
					res+="**";
				}
				if(score >= 0.25 && score < 1){
					System.out.println("***");
					res+="***";
				}
				if(score >= 1){
					System.out.println("****");
					res+="****";
				}
				
				//System.out.println("Done called: "+System.currentTimeMillis());
				
			//}



		}catch(Exception ex){
			ex.printStackTrace();
		}
		return res;
	}

	private static void deleteFile() {
		// TODO Auto-generated method stub
		File f = new File("./");
		if (f.isDirectory()) {
			String[] files = f.list();
			for (int i = 0; i < files.length; i++) {
				if(!files[i].equalsIgnoreCase("train_h221_s221.dat"))
					if(files[i].endsWith(".xml") || files[i].endsWith(".dat")){
						//System.out.println(files[i]);
						File f1 = new File(files[i]);
						f1.delete();
					}

			}
		}

		f = new File("demo");
		if (f.isDirectory()) {
			String[] files = f.list();
			for (int i = 0; i < files.length; i++) {
				if(files[i].endsWith(".xml")){
					//System.out.println(files[i]);
					File f1 = new File( "demo/" +files[i]);
					f1.delete();
				}
			}
		}
		f = new File("demotranslated");
		if (f.isDirectory()) {
			String[] files = f.list();
			for (int i = 0; i < files.length; i++) {
				if(files[i].endsWith(".xml")){
					//System.out.println(files[i]);
					File f1 = new File("demotranslated/" +files[i]);
					f1.delete();
				}
			}
		}
	}

	private static String getTagValue(String sTag, Element eElement) {
		NodeList nlList = eElement.getElementsByTagName(sTag).item(0).getChildNodes();
		Node nValue = (Node) nlList.item(0);
		String ret="";
		if(nValue!=null) ret=nValue.getNodeValue();
		return ret;
	}

	public static String translate(String param,String fromlang){
		String[] res = param.trim().split(" ");
		String req="";
		for(int i=0;i<res.length;i++) {
			//System.out.println(res[i]);
			if(!res[i].equals("。")){
				req+=res[i] + "%20";
			}

		}

		param=req;

		String url = "http://translate.google.com/translate_t?langpair="+fromlang + "|en&text=" + param;
		//System.out.println("Transformed URL : " + url);
		String response="";
		try{
			URL yahoo = new URL(url);
			URLConnection yc = yahoo.openConnection();
			yc.setRequestProperty("User-Agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; .NET CLR 1.2.30703)");
			BufferedReader in = new BufferedReader(
					new InputStreamReader(
							yc.getInputStream()));
			String inputLine;


			while ((inputLine = in.readLine()) != null){ 
				response+=inputLine;
			}
			////System.out.print(response);
			in.close();
		}catch (Exception e) {
			// TODO: handle exception
		}
		String tmp_res=null;
		try{
			////System.out.println("response " +response);
			String result=response.split("onmouseout=\"this.style.backgroundColor=\'#fff\'")[1];
			tmp_res= result.split("</span")[0];
			tmp_res= tmp_res.substring(2);


			//System.out.println("Translated : " + tmp_res);
		}catch (Exception e) {
			e.printStackTrace();
		}

		try{
			Thread.sleep(40);
		}catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
			return param;
		}
		return tmp_res.replaceAll("%20", " ");

	}

}
