/* 
 * @author: Ayon Chakraborty
 * @course project: Network Security
 * @school: SUNY Stony Brook 
 *
 */
 
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.*;

import javax.swing.*;
import javax.swing.UIManager;

import javax.swing.JApplet;

public class SampleTestGUI extends JApplet {
  public void init() {
    try {
      javax.swing.SwingUtilities.invokeAndWait(new Runnable() {
        public void run() {
          createGUI();
        }
      });
    } catch (Exception e) {
      System.err.println("createGUI didn't successfully complete");
    }
  }
 
  private void createGUI() {
   
		getContentPane().setLayout(new FlowLayout());
	  
		final Button l1 = new Button("User A");
		l1.setFont(new Font("Serif", Font.PLAIN, 24));
		getContentPane().add(l1);
		
		final JTextField t1= new JTextField(10);
		t1.setSize(100, 400);
		t1.setFont(new Font("Serif", Font.PLAIN, 20));
		getContentPane().add(t1);

		ImageIcon ii=new ImageIcon("arrow.gif");
		final JLabel l3 = new JLabel(ii);
		getContentPane().add(l3);
		
		final Button l2 = new Button("User B");
		l2.setFont(new Font("Serif", Font.PLAIN, 24));
		getContentPane().add(l2);
		
		final JTextField t2= new JTextField(10);
		t2.setSize(100, 400);
		t2.setFont(new Font("Serif", Font.PLAIN, 20));
		getContentPane().add(t2);
		
		final JLabel l4 = new JLabel("Prediction:");
		l4.setFont(new Font("Serif", Font.PLAIN, 24));
		getContentPane().add(l4);
		
		
		final JTextField t3= new JTextField(20);
		t3.setSize(100, 400);
		t3.setFont(new Font("Serif", Font.PLAIN, 20));
		getContentPane().add(t3);


		
		JButton b=new JButton("Analyse");
		b.setFont(new Font("Serif", Font.PLAIN, 24));
		b.addActionListener(new ActionListener() {

			public void actionPerformed(ActionEvent e)
			{
				//Execute when button is pressed
				try{
					SampleTest demo = new SampleTest();
					t3.setText("Analsing...");
					//System.out.println("testing ");
					String res = demo.analyse(t1.getText().trim(),t2.getText().trim());
					//System.out.println(res);
					t3.setText(res);
				}catch (Exception e1) {
					// TODO: handle exception
					e1.printStackTrace();
				}
			}
		});      
		
		getContentPane().add(b);
		setSize(299,270);
		getContentPane().setVisible(true);
		
		
	
	}
  }



