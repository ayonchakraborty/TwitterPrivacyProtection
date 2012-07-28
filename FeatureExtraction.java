/* 
 * @author: Ayon Chakraborty
 * @course project: Network Security
 * @school: SUNY Stony Brook 
 *
 */
 
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;


public class FeatureExtraction {

	
	private static int msgclusters;
	private static int totNumHashtags=34;
	
	private static File trainFile=new File("E:/Network Security/Project/Model/ham_221.dat");
	private static File testFile=new File("E:/Network Security/Project/Model/test.dat");
	private static String spam = "E:/Network Security/Project/ALLFAKEPROFILES";
	private static String ham="E:/Network Security/Project/hamprofilestranslated";
	
	private enum fofo{
		zerofriendszerofollowers,zerofriends,zerofollowers;
	}
	
	public static File generateDat(File fn, NaiveBayes nb) throws Exception{
			File datFile=new File(fn.getParent()+fn.getName().substring(0, fn.getName().indexOf(".")-1)+"_dt.dat");
			FileWriter writer=new FileWriter(datFile);
			
			DateFormat formatter = null ; 
			DecimalFormat df = new DecimalFormat("#.####");
			Date date = null ;
			
		
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = null;

			File dir=new File(ham);
			File[] files=dir.listFiles();
			
			int counter=1;
				
			//System.out.println(counter);
			counter++;
			
			ArrayList<String> tweets=new ArrayList<String>();
			ArrayList<Long> ts=new ArrayList();
			ArrayList<String> profiledata = new ArrayList<String>();
			
				doc = dBuilder.parse(fn);
				doc.getDocumentElement().normalize();
				//System.out.println("Root element :" + doc.getDocumentElement().getNodeName());
				populateTweetData(doc,tweets,formatter,date,ts);
				populateProfileData(doc, profiledata);
				
				writer.write("1 ");
				
				if(ts.size()>1){
					long avgTimeBetPosts=getAvgTimeBetPosts(ts);
					writer.write("1:"+avgTimeBetPosts+" ");
					
					long maxIdleDuration=getMaxIdleDuration(ts);
					writer.write("2:"+maxIdleDuration+" ");
				}
				
				if(tweets.size()>0){
					double avgPostLen=getAvgTweetLength(tweets,df);
					writer.write("3:"+avgPostLen+" ");
					
					double avgReTweets=avgRetweetsPerTweet(tweets,df);
					writer.write("4:"+avgReTweets+" ");
					
					double avgMentionsPerTweet=avgMentionsPerTweet(tweets,df);
					writer.write("5:"+avgMentionsPerTweet+" ");
					
					double avgSameURLCount=avgSameURLCount(tweets,df);
					writer.write("6:"+avgSameURLCount+" ");
					
					double avgSameHashTagLCount=avgSameHashTagCount(tweets,df);
					writer.write("7:"+avgSameHashTagLCount+" ");
										
					msgclusters=avgmsgclusters(tweets);
					double msgSimilarity=Double.parseDouble(df.format(tweets.size()/msgclusters));
					writer.write("8:"+msgSimilarity+" ");
					
					int spams=0,spamCount=0;
					for(int k=0;k<tweets.size();k++){
						spams = nb.analyseData(tweets.get(k));
						if(spams==2){
							spamCount++;
						}
						
					}
					
					double avgSpamPostCount=Double.parseDouble(df.format(spamCount/tweets.size()));
					writer.write("9:"+avgSpamPostCount+" ");
				}
				
				if(profiledata.size()>0){
					int prof_desc= nb.analyseData(profiledata.get(8));
					writer.write("10:"+prof_desc+" ");
					
					double followerCount=getFollowerCount(profiledata);
					writer.write("11:"+followerCount+" ");
					
					double friendCount=getFriendCount(profiledata);
					writer.write("12:"+friendCount+" ");
					
					double fofoRatio=Double.parseDouble(df.format(getFoFoRatio(profiledata)));
					writer.write("13:"+fofoRatio+" ");
					
					double reputation=Double.parseDouble(df.format(getReputation(profiledata)));
					writer.write("14:"+reputation+" ");
					
					double profileImage=getProfileImage(profiledata);
					writer.write("15:"+profileImage+" ");
					
					long profileAge=getProfileAge(profiledata);
					writer.write("16:"+profileAge+" ");
					
					int listCount=getListCount(profiledata);
					writer.write("17:"+listCount+" ");
					try{
						double tweetsPerDay=Double.parseDouble(df.format(getTweetsperDay(profiledata)));
						writer.write("18:"+tweetsPerDay+" ");	
					}catch (Exception e) {
						// TODO: handle exception
						//double tweetsPerDay=Double.parseDouble(df.format(getTweetsperDay(profiledata)));
						writer.write("18:"+"0"+" ");
					}
					
					
					int nameFeature= nb.analyseData(getName(profiledata));
					writer.write("19:"+nameFeature+" ");
					
					int screenNameFeature= nb.analyseData(getScreenName(profiledata));
					writer.write("20:"+screenNameFeature+" ");
				}
				
				if(tweets.size()>0 && profiledata.size()>0){
					double urlPerTweet=Double.parseDouble(df.format(getURLperTweet(profiledata, tweets)));
					writer.write("21:"+urlPerTweet+" ");
					
					double urlRatio=Double.parseDouble(df.format(getURLRatio(profiledata, tweets)));
					writer.write("22:"+urlRatio+" ");
					
					double hashTagsPerTweet=Double.parseDouble(df.format(getHashtagsperTweet(profiledata, tweets)));
					writer.write("23:"+hashTagsPerTweet+" ");
					
					double hashTagRatio=Double.parseDouble(df.format(getHashtagRatio(profiledata, tweets)));
					writer.write("24:"+hashTagRatio+" ");
				}
				

			
			writer.close();
			return datFile;
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		NaiveBayes nb = new NaiveBayes();
		nb.trainOnData();
		
		try{
			
			FileWriter writer=new FileWriter(trainFile);
			
			DateFormat formatter = null ; 
			DecimalFormat df = new DecimalFormat("#.####");
			Date date = null ;
			
		
			DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			Document doc = null;

			File dir=new File(ham);
			File[] files=dir.listFiles();
			
			int counter=1;
			for(int i=0;i<221;i++){
			try{
				
			//System.out.println(counter);
			counter++;
			
			ArrayList<String> tweets=new ArrayList<String>();
			ArrayList<Long> ts=new ArrayList();
			ArrayList<String> profiledata = new ArrayList<String>();
			
				doc = dBuilder.parse(files[i]);
				doc.getDocumentElement().normalize();
				//System.out.println("Root element :" + doc.getDocumentElement().getNodeName());
				populateTweetData(doc,tweets,formatter,date,ts);
				populateProfileData(doc, profiledata);
				
				writer.write("1 ");
				
				if(ts.size()>1){
					long avgTimeBetPosts=getAvgTimeBetPosts(ts);
					writer.write("1:"+avgTimeBetPosts+" ");
					
					long maxIdleDuration=getMaxIdleDuration(ts);
					writer.write("2:"+maxIdleDuration+" ");
				}
				
				if(tweets.size()>0){
					double avgPostLen=getAvgTweetLength(tweets,df);
					writer.write("3:"+avgPostLen+" ");
					
					double avgReTweets=avgRetweetsPerTweet(tweets,df);
					writer.write("4:"+avgReTweets+" ");
					
					double avgMentionsPerTweet=avgMentionsPerTweet(tweets,df);
					writer.write("5:"+avgMentionsPerTweet+" ");
					
					double avgSameURLCount=avgSameURLCount(tweets,df);
					writer.write("6:"+avgSameURLCount+" ");
					
					double avgSameHashTagLCount=avgSameHashTagCount(tweets,df);
					writer.write("7:"+avgSameHashTagLCount+" ");
										
					msgclusters=avgmsgclusters(tweets);
					double msgSimilarity=Double.parseDouble(df.format(tweets.size()/msgclusters));
					writer.write("8:"+msgSimilarity+" ");
					
					int spams=0,spamCount=0;
					for(int k=0;k<tweets.size();k++){
						spams = nb.analyseData(tweets.get(k));
						if(spams==2){
							spamCount++;
						}
						
					}
					
					double avgSpamPostCount=Double.parseDouble(df.format(spamCount/tweets.size()));
					writer.write("9:"+avgSpamPostCount+" ");
				}
				
				if(profiledata.size()>0){
					int prof_desc= nb.analyseData(profiledata.get(8));
					writer.write("10:"+prof_desc+" ");
					
					double followerCount=getFollowerCount(profiledata);
					writer.write("11:"+followerCount+" ");
					
					double friendCount=getFriendCount(profiledata);
					writer.write("12:"+friendCount+" ");
					
					double fofoRatio=Double.parseDouble(df.format(getFoFoRatio(profiledata)));
					writer.write("13:"+fofoRatio+" ");
					
					double reputation=Double.parseDouble(df.format(getReputation(profiledata)));
					writer.write("14:"+reputation+" ");
					
					double profileImage=getProfileImage(profiledata);
					writer.write("15:"+profileImage+" ");
					
					long profileAge=getProfileAge(profiledata);
					writer.write("16:"+profileAge+" ");
					
					int listCount=getListCount(profiledata);
					writer.write("17:"+listCount+" ");
					
					double tweetsPerDay=Double.parseDouble(df.format(getTweetsperDay(profiledata)));
					writer.write("18:"+tweetsPerDay+" ");
					
					int nameFeature= nb.analyseData(getName(profiledata));
					writer.write("19:"+nameFeature+" ");
					
					int screenNameFeature= nb.analyseData(getScreenName(profiledata));
					writer.write("20:"+screenNameFeature+" ");
				}
				
				if(tweets.size()>0 && profiledata.size()>0){
					double urlPerTweet=Double.parseDouble(df.format(getURLperTweet(profiledata, tweets)));
					writer.write("21:"+urlPerTweet+" ");
					
					double urlRatio=Double.parseDouble(df.format(getURLRatio(profiledata, tweets)));
					writer.write("22:"+urlRatio+" ");
					
					double hashTagsPerTweet=Double.parseDouble(df.format(getHashtagsperTweet(profiledata, tweets)));
					writer.write("23:"+hashTagsPerTweet+" ");
					
					double hashTagRatio=Double.parseDouble(df.format(getHashtagRatio(profiledata, tweets)));
					writer.write("24:"+hashTagRatio+" ");
				}
				
				
/*				System.out.print(", no of spam tweets : " + spams);
				if(spams >= tweets.size()/5 || spams >= 10 || prof_desc==2 || msgclusters>1.2 ){
					System.out.print(", - spam profile ");
				}else{
					System.out.print(", - non spam profile ");
				}*/
				
				
				//System.out.println("");
			}catch (Exception e) {
				// TODO: handle exception
			}
			
				writer.write("\n");
			}
			
			writer.close();
		}catch(Exception ex){
			ex.printStackTrace();
		}
	}
	
	 private static void populateTweetData(Document doc, ArrayList<String> tweets, DateFormat formatter, Date date, ArrayList<Long> ts) throws ParseException {
		// TODO Auto-generated method stub
			NodeList nList = doc.getElementsByTagName("tweet");
			for(int temp = 0; temp < nList.getLength(); temp++){
				Node nNode = nList.item(temp);
				if (nNode.getNodeType() == Node.ELEMENT_NODE) {
					Element eElement = (Element) nNode;
					String text=getTagValue("text", eElement);
					tweets.add(text);
				    formatter = new SimpleDateFormat("EEE MMM d HH:mm:ss Z yyyy");
					date = (Date)formatter.parse(getTagValue("created_at", eElement)); 
					long time=date.getTime();
					ts.add(time);
				}
			}
	}
	
	private static void populateProfileData(Document doc, ArrayList<String> profiledata) throws ParseException {
		
				Node nNode = doc.getElementsByTagName("root").item(0);
				if (nNode.getNodeType() == Node.ELEMENT_NODE) {
					Element eElement = (Element) nNode;
					
					String name=getTagValue("name", eElement); // 0
					profiledata.add(name);
					
					String screenname=getTagValue("screen_name", eElement); // 1
					profiledata.add(screenname);
					
					String followers=getTagValue("followers_count", eElement); // 2
					profiledata.add(followers);
					
					String friends=getTagValue("friends_count", eElement); // 3
					profiledata.add(friends);
					
					String image=getTagValue("default_profile_image", eElement); // 4
					profiledata.add(image);
										
					String createtime=getTagValue("created_at", eElement); //5
					profiledata.add(createtime);
					
					String listedcount=getTagValue("listed_count", eElement); // 6
					profiledata.add(listedcount);
					
					String tweetcount=getTagValue("tweet_count", eElement); // 7
					profiledata.add(tweetcount);
					
					String profdesc=getTagValue("description", eElement); // 8
					profiledata.add(profdesc);
					
					
					String profid=getTagValue("id", eElement); // 9
					profiledata.add(profid);
					
				}
		}
	
	private static String getName(ArrayList<String> profilevector){
		return profilevector.get(0);
	}
	
	private static String getScreenName(ArrayList<String> profilevector){
		return profilevector.get(1);
	}
	
	private static int getFollowerCount(ArrayList<String> profilevector){
		return Integer.parseInt(profilevector.get(2));
	}
	
	private static int getFriendCount(ArrayList<String> profilevector){
		return Integer.parseInt(profilevector.get(3));
	}
	
	private static double getFoFoRatio(ArrayList<String> profilevector){
		float x = getFriendCount(profilevector);
		float y = getFollowerCount(profilevector);
		if(x!=0 && y != 0) return (x/y);
		else return 0;
/*		else if(x == 0 && y == 0) return "zerofriendszerofollowers";
		else if(x == 0) return "zerofriends";
		else if(y == 0) return "zerofollowers";
		return "";*/
	}
	
	private static double getReputation(ArrayList<String> profilevector){
		float x = getFriendCount(profilevector);
		float y = getFollowerCount(profilevector);
		
		double rep=0;
		if((x+y)!=0){
			rep=(y/(x+y));
		}
		return rep;
		
/*		if(x+y==0) return "zerofriendszerofollowers";
		else if(y == 0) return "zerofollowers";
		else if(x == 0) return "zerofriends";
		return ""+(y/(x+y));*/
	
	}
	
	private static int getProfileImage(ArrayList<String> profilevector){
		int feature=0;
		String flag=profilevector.get(4);
		if(flag=="true"){
			feature=1;
		}
		return feature;
	}
	
	private static long getProfileAge(ArrayList<String> profilevector) throws Exception{
		long now = System.currentTimeMillis();
		DateFormat formatter = new SimpleDateFormat("EEE MMM d HH:mm:ss Z yyyy");
		Date date = (Date)formatter.parse(profilevector.get(5)); 
		long time = date.getTime();
		return now - time;
	}
	
	private static int getListCount(ArrayList<String> profilevector){
		return Integer.parseInt(profilevector.get(6));
	}
	
	private static double getURLperTweet(ArrayList<String> profilevector, ArrayList<String> tweetlist){
		double tweets = Float.parseFloat(profilevector.get(7));
		String[] temp;
		int count = 0;
        
		for(int i=0; i< tweetlist.size(); i++){
			temp = tweetlist.get(i).split("http://") ;
			count += (temp.length - 1);
		}
		return (count/tweets);
	}
	
	private static double getURLRatio(ArrayList<String> profilevector, ArrayList<String> tweetlist){
		String[] temp;
		int averageurlperuser = 10; /* shall be computed on our data */
		int count = 0;
        
		for(int i=0; i< tweetlist.size(); i++){
			temp = tweetlist.get(i).split("http://") ;
			count += (temp.length - 1);
		}
		return (count/averageurlperuser);
	}
	
	private static double getHashtagsperTweet(ArrayList<String> profilevector, ArrayList<String> tweetlist){
		double tweets = Float.parseFloat(profilevector.get(7));
		String[] temp;
		int count = 0;
        
		for(int i=0; i< tweetlist.size(); i++){
			temp = tweetlist.get(i).split("#") ;
			count += (temp.length - 1);
		}
		return (count/tweets);
	}
	
	private static double getHashtagRatio(ArrayList<String> profilevector, ArrayList<String> tweetlist){
		String[] temp;
		int averagehashperuser = totNumHashtags; /* shall be computed on our data */
		int count = 0;
        
		for(int i=0; i< tweetlist.size(); i++){
			temp = tweetlist.get(i).split("#") ;
			count += (temp.length - 1);
		}
		return (count/averagehashperuser);
	}
		
	private static double getTweetsperDay(ArrayList<String> profilevector) throws Exception{
		try{
			double tweets = Float.parseFloat(profilevector.get(7));
			long age = getProfileAge(profilevector);
			double days = (age)/(86400000); /* milliseconds in a day */
			return (tweets/days);
		}catch (Exception e) {
			// TODO: handle exception
			return 1;
		}
		
	}

	private static String getTagValue(String sTag, Element eElement) {
		 NodeList nlList = eElement.getElementsByTagName(sTag).item(0).getChildNodes();
		 Node nValue = (Node) nlList.item(0);
		 String ret="";
		 if(nValue!=null) ret=nValue.getNodeValue();
		 return ret;
	 }
	 
	 private static long getAvgTimeBetPosts(ArrayList<Long> ts){
			long tDiff=0;
			for(int i=0;i<ts.size()-1;i++){
				tDiff=tDiff+(ts.get(i)-ts.get(i+1));
			}
			
			long avgTimeBetPosts=tDiff/(ts.size()-1);
			return avgTimeBetPosts;
	 }
	 
	 private static long getMaxIdleDuration(ArrayList<Long> ts){
		 	ArrayList<Long> timeGapList=new ArrayList<Long>();
			long tDiff=0;
			for(int i=0;i<ts.size()-1;i++){
				tDiff=ts.get(i)-ts.get(i+1);
				timeGapList.add(tDiff);
			}
			
			Collections.sort(timeGapList, Collections.reverseOrder());
			
			return timeGapList.get(0);
	 }
	 
	 private static double getAvgTweetLength(ArrayList<String> tweets, DecimalFormat df){
		 double avgTweetLen=0, tmp=0;
		 for(String tweet:tweets){
			 tmp=tmp+tweet.length();
		 }
		 
		 avgTweetLen=tmp/tweets.size();
		 return Double.parseDouble(df.format(avgTweetLen));
	 }
	 
	 private static double avgRetweetsPerTweet(ArrayList<String> tweets, DecimalFormat df){
		 double avgReTweets=0, tmp=0;
		 for(String tweet:tweets){
			 String[] tSplit=tweet.split(" ");
			 for(String rt:tSplit){
				 if(rt.equals("RT")) tmp++;
			 }
		 }
		 
		 avgReTweets=tmp/tweets.size();
		 return Double.parseDouble(df.format(avgReTweets));
	 }
	 
	 private static double avgMentionsPerTweet(ArrayList<String> tweets, DecimalFormat df){
		 double avgMentions=0, tmp=0;
		 for(String tweet:tweets){
			 String[] tSplit=tweet.split(" ");
			 for(String mention:tSplit){
				 if(mention.contains("@")) tmp++;
			 }
		 }
		 
		 avgMentions=tmp/tweets.size();
		 return Double.parseDouble(df.format(avgMentions));
	 }
	 

		private static int avgmsgclusters(ArrayList<String> tweets) {
			// TODO Auto-generated method stub
			String[][] matrix =  new String[200][140];
			for(int k=0;k<200;k++){
				for(int i=0;i<140;i++){
					matrix[k][i] = null;
				}
			}
			for(int k=0;k<tweets.size();k++){
				//System.out.println("sundi " + );
				String[] parse = tweets.get(k).split(" ");
				for(int i=0;i<parse.length;i++){
					matrix[k][i] = parse[i] ;
				}
			}
			int numclusters=0;
			int permnearestcluster=0;
			int mindist=2;
			int closestdistance=0;
			ArrayList<ArrayList<String>> clusters =  new ArrayList<ArrayList<String>>();
			ArrayList cluster1= new ArrayList<String>();
			cluster1.add(tweets.get(0));
			clusters.add(cluster1);
			for(int k=1;k<tweets.size();k++){
				int nearestcuster=-1;
				
				for(int j=0;j<clusters.size();j++){
					
					int dist =  distance_tweet_clusters(tweets.get(k), clusters.get(j),matrix,tweets);
					//System.out.println("sundi " + dist  + " , " + k);
					if(dist <= mindist && dist > -1){
						nearestcuster=j;
						if(nearestcuster < permnearestcluster){
							permnearestcluster = nearestcuster;
						}
						closestdistance=2;
						     
					}else if(dist > -1){
						closestdistance=dist;
					}


				}
				if(closestdistance >2){
					
					ArrayList clusterNew= new ArrayList<String>();
					clusterNew.add(tweets.get(k));
					clusters.add(clusterNew);
					
				}else{
					clusters.get(permnearestcluster).add(tweets.get(k));
				}
				
			}

			numclusters = clusters.size();
			return numclusters;
		}

		private static int distance_tweet_clusters(String tmptwt,
				ArrayList<String> arrayList, String[][] matrix, ArrayList<String> tweets) {
			// TODO Auto-generated method stub
			//System.out.println("sundi 12 " + tmptwt);
			int index=tweets.indexOf((tmptwt));
			int highlysim=0;
			if(index==-1)
				return -1;
			for(int k=0;k<arrayList.size();k++){
				//System.out.println("sundi 123 " + arrayList.get(k));
				int indextmp=tweets.indexOf((arrayList.get(k)));
				if(indextmp==-1)
					return -1;
				int similar=0;
				for(int i=0;i<140;i++){
					if(matrix[index][i] == null || matrix[indextmp][i]==null ||
							matrix[index][i].trim()=="" || matrix[indextmp][i].trim()=="")
						continue;
					String tmpmat = matrix[index][i];
					String tmpmatind = matrix[indextmp][i];
					//System.out.println("sundi 1234 " + tmpmat);
					//System.out.println("sundi 12345 " + tmpmatind);
					int dist = editDistance ( tmpmat, tmpmatind);
					if(dist <= 2){
						
						//System.out.println("sundi sim " );
							similar++;
//							if(highlysim < similar){
//								highlysim=similar;	
//							}
						
					}
				}
				int tmp =tmptwt.split(" ").length;
				if(highlysim < (tmp-similar))
					highlysim = tmp-similar;
				
				
			}
			//highlysim = tmptwt.split(" ").length -highlysim;
			return highlysim;
		}

		public static int editDistance(String s, String t){
		    int m=s.length();
		    int n=t.length();
		    int[][]d=new int[m+1][n+1];
		    for(int i=0;i<=m;i++){
		      d[i][0]=i;
		    }
		    for(int j=0;j<=n;j++){
		      d[0][j]=j;
		    }
		    for(int j=1;j<=n;j++){
		      for(int i=1;i<=m;i++){
		        if(s.charAt(i-1)==t.charAt(j-1)){
		          d[i][j]=d[i-1][j-1];
		        }
		        else{
		          d[i][j]=min((d[i-1][j]+1),(d[i][j-1]+1),(d[i-1][j-1]+1));
		        }
		      }
		    }
		    return(d[m][n]);
		  }
		  public static int min(int a,int b,int c){
		    return(Math.min(Math.min(a,b),c));
		  }
		  
			 private static double avgSameURLCount(ArrayList<String> tweets,
						DecimalFormat df) {
					 double avgSameURLCount=0, tmp=0; HashSet<String> tmpSet=new HashSet<String>();
					 for(String tweet:tweets){
						 String[] tSplit=tweet.split(" ");
						 for(String s:tSplit){
							 if(s.contains("http://")){
								 tmp++;
								 tmpSet.add(s);
							 }
						 }
					 }
					 
					 if(tmpSet.size()>0) avgSameURLCount=tmp/(tmpSet.size()*tweets.size());
					 return Double.parseDouble(df.format(avgSameURLCount));
				}
				 
				 private static double avgSameHashTagCount(ArrayList<String> tweets,
							DecimalFormat df) {
						 double avgSameHashTagCount=0, tmp=0; HashSet<String> tmpSet=new HashSet<String>();
						 for(String tweet:tweets){
							 String[] tSplit=tweet.split(" ");
							 for(String s:tSplit){
								 if(s.contains("#")){
									 tmp++;
									 tmpSet.add(s);
								 }
							 }
						 }
						 
						 if(tmpSet.size()>0) avgSameHashTagCount=tmp/(tmpSet.size()*tweets.size());
						 return Double.parseDouble(df.format(avgSameHashTagCount));
					}		  



}
