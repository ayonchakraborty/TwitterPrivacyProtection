/* 
 * @author: Ayon Chakraborty
 * @course project: Network Security
 * @school: SUNY Stony Brook 
 *
 */
 
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.Reader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import weka.classifiers.bayes.NaiveBayesUpdateable;
import weka.classifiers.functions.SMO;
import weka.classifiers.meta.FilteredClassifier;
import weka.core.Instance;
import weka.core.Instances;
import weka.core.converters.ConverterUtils.DataSource;
import weka.filters.Filter;
import weka.filters.unsupervised.attribute.NumericToNominal;


public class Classifier {

	/**
	 * @param args
	 * @throws Exception 
	 */
	
	public static SMO train(Instances train, NumericToNominal ntn) throws Exception{
		//Classification

		for (int i = 0; i < train.numInstances(); i++) {
			 ntn.input(train.instance(i));
		 }
		 ntn.batchFinished();
		 Instances newData = ntn.getOutputFormat();
			  
		 Instance processed;
		 while ((processed = ntn.output()) != null) {
			 newData.add(processed);
		 }
		 
		 // classifier
		 SMO nb = new SMO();

		 // train and make predictions
		 nb.buildClassifier(newData);
		 
		 return nb;
	}
	
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try{
			//Classification
			 DataSource source = new DataSource("E:/Network Security/Project/Model/train_new.dat");
			 Instances train = source.getDataSet();
			 source = new DataSource("E:/Network Security/Project/Model/test_v2.dat");
			 Instances test = source.getDataSet();
			 
			 NumericToNominal ntn=new NumericToNominal();
			 ntn.setInputFormat(train);
	
			 for (int i = 0; i < train.numInstances(); i++) {
				 ntn.input(train.instance(i));
			 }
			 ntn.batchFinished();
			 Instances newData = ntn.getOutputFormat();
				  
			 Instance processed;
			 while ((processed = ntn.output()) != null) {
				 newData.add(processed);
			 }
			 
			 for (int i = 0; i < test.numInstances(); i++) {
				 ntn.input(test.instance(i));
			 }
			 ntn.batchFinished();
			 Instances newTestData = ntn.getOutputFormat();
				  
			 Instance processedTest;
			 while ((processedTest = ntn.output()) != null) {
				 newTestData.add(processedTest);
			 }
					  
			 
			 // classifier
			 NaiveBayesUpdateable nb = new NaiveBayesUpdateable();
	
			 // train and make predictions
			 nb.buildClassifier(newData);
	
			 
			 for (int i = 0; i < newTestData.numInstances(); i++) {
				   double pred = nb.classifyInstance(newTestData.instance(i));
				   //System.out.print("ID: " + test.instance(i).value(0));
				   System.out.print(", actual: " + newTestData.classAttribute().value((int) newTestData.instance(i).classValue()));
				   System.out.println(", predicted: " + newTestData.classAttribute().value((int) pred));
			 }
		}
		catch(Exception ex){
			ex.printStackTrace();
		}
	}

}
