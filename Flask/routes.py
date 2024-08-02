from flask import render_template, url_for, flash, redirect, request
from Flask import app, db, bcrypt
from Flask.models import User
from flask import Flask,render_template,request, redirect,url_for,flash,session
from Flask.models import db,User,Campaign,AdRequest,FlaggedUser
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from flask_login import login_required,login_user,logout_user



@app.route('/')
@app.route('/home')
def landing_page():
    user_id = session.get('user_id')
    if not user_id:
        return render_template('landing_page.html')

    user = User.query.get_or_404(user_id)
    if user.role == 'influencer':
        return redirect(url_for('iprofile'))
    if user.role == 'sponsor':
        return redirect(url_for('sprofile'))
    if user.role =='admin':
        return redirect(url_for('admin_dash'))
        
    
# Login Page for both User and Influencer
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user:
            # Check if the user is flagged
            flagged_user = FlaggedUser.query.filter_by(user_id=user.id).first()
            if flagged_user:
                flash('Your account is flagged. Please contact admin. for assistance', 'danger')
                logout_user()
                return redirect(url_for('login'))
            
            # Validate password
            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['role'] = user.role
                
                # Log the user in
                login_user(user)
                
                # Redirect based on user role
                if user.role == 'sponsor':
                    return redirect(url_for('sprofile'))
                elif user.role == 'influencer':
                    return redirect(url_for('iprofile'))
            else:
                flash('Invalid username or password', 'danger')
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

# Admin Login Page
@app.route('/Alogin', methods=['GET', 'POST'])
def Alogin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username,role='admin').first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dash'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('Alogin.html')


# Sponsor signup
@app.route('/Ssignup', methods=['GET', 'POST'])
def Ssignup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        company_name = request.form['company_name']
        industry = request.form['industry']
        budget = float(request.form['budget'])

        # Validate form data
        if not username or not password or not company_name or not industry or not budget:
            flash('Please fill out all fields.', 'danger')
            return redirect(url_for('Ssignup'))

        # Create new sponsor user
        new_user = User(
            username=username,
            password=generate_password_hash(password),
            role='sponsor',
            company_name=company_name,
            name=None,
            category=industry,
            niche=None,
            reach=None,
            budget=budget,
            platforms=None,
            blacklist=False
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username already exists. Please choose a different username.', 'danger')

    return render_template('Ssignup.html')



# Influencer Signup
@app.route('/Isignup', methods=['GET', 'POST'])
def Isignup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        name = request.form['name']
        category = request.form['category']
        niche = request.form['niche']
        reach = int(request.form['reach'])
        platforms = ','.join(request.form.getlist('platforms'))

        new_user = User(
            username=username,
            password=generate_password_hash(password),
            role='influencer',
            company_name=None,
            name=name,
            category=category,
            niche=niche,
            reach=reach,
            budget=None,
            platforms=platforms,
            blacklist=False
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username already exists. Please choose a different username.', 'danger')
    
    return render_template('Isignup.html')

@app.route('/logout')
def logout():
    logout_user()
    return render_template('landing_page.html')

@app.route("/iprofile",methods=['GET','POST'])
@login_required
def iprofile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    

    user = User.query.get_or_404(user_id)
    if user.role == 'sponsor':
        return redirect(url_for('sprofile'))

    profile = {
        'username': user.username,
        'name': user.name,
        'category': user.category,
        'niche': user.niche,
        'reach': user.reach,
        'platforms': user.platforms.split(',') if user.platforms else [],
        'ratings': 4.5,  # This should be calculated based on actual data
        'earnings': 1000,  # This should be calculated based on actual data
        'campaign_progress': 75,  # This should be calculated based on actual data
    }

    sponsor_requests = AdRequest.query.filter_by(influencer_name=user.username,status='NIL').all()
    accepted_requests = AdRequest.query.filter_by(influencer_name=user.username,status='accept').all()
    reg_requests= AdRequest.query.filter_by(influencer_name=user.username,status='renegotiate').all()
    rejected_requests = AdRequest.query.filter_by(influencer_name=user.username,status="reject").all()
    return render_template('Iprofile.html', profile=profile, sponsor_requests=sponsor_requests,accepted_requests=accepted_requests,rejected_requests=rejected_requests,reg=reg_requests)

@app.route('/update_profile', methods=['POST','GET'])
@login_required
def update_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('user_login'))

    user = User.query.get_or_404(user_id)
    if user.role != 'influencer':
        return redirect(url_for('user_login'))

    user.username = request.form['username']
    user.name = request.form['name']
    user.category = request.form['category']
    user.niche = request.form['niche']
    user.reach = request.form['reach']
    user.platforms = ','.join(request.form.getlist('platforms'))

    db.session.commit()
    flash('Profile updated successfully!', 'success')
    
    return redirect(url_for('iprofile'))

@app.route('/Ifind',methods=['GET','POST'])
@login_required
def Ifind():
    results1 = None
    if request.method == 'POST':
        search_query = request.form['search_query'].lower()
        
        # Search logic for users and campaigns
        users = User.query.filter(
            (User.role=='sponsor')&
            ((User.username.ilike(f"%{search_query}%")) |
            (User.company_name.ilike(f"%{search_query}%")) |
            (User.name.ilike(f"%{search_query}%")) |
            (User.category.ilike(f"%{search_query}%")) |
            (User.niche.ilike(f"%{search_query}%"))
        )).all()
        
        campaigns = Campaign.query.filter(
            (Campaign.campaign_name.ilike(f"%{search_query}%")) |
            (Campaign.category.ilike(f"%{search_query}%")) |
            (Campaign.products.ilike(f"%{search_query}%")) |
            (Campaign.goals.ilike(f"%{search_query}%"))
        ).all()
        
        results1 = {
            'users': users,
            'campaigns': campaigns
        }

    return render_template('ifind.html',results1=results1)

@app.route('/Istat')
@login_required
def Istat():
    return render_template('Istat.html')


@app.route('/request_action/<int:request_id>/<action>', methods=['GET'])
def request_action(request_id, action):
    user_id = session.get('user_id')
    if user_id is None:
        flash('User not logged in.', 'error')
        return redirect(url_for('login'))  # Redirect to login if user is not logged in
    
    user = User.query.get_or_404(user_id)
    sponsor_requests = AdRequest.query.filter_by(influencer_name=user.username).all()
    
    for request in sponsor_requests:
        if request.id == request_id:
            if action in ['accept', 'reject']:
                request.status = action
                db.session.commit()  # Save changes to the database
                flash(f'Request {action}ed successfully.', 'success')
            elif action == 'renegotiate':
                new_budget = request.form.get('new_budget')
                if new_budget:
                    try:
                        print(request.action)
                        request.budget = float(new_budget)
                        db.session.commit()  # Save changes to the database
                        print(request.action)
                        flash('Request renegotiated successfully.', 'success')
                    except ValueError:
                        flash('Invalid budget value.', 'error')
                else:
                    flash('No budget value provided for renegotiation.', 'error')
            else:
                flash('Invalid action.', 'error')
            break
    else:
        flash('Request not found.', 'error')
    
    return redirect(url_for('iprofile'))


@app.route('/request_action/<int:request_id>/renegotiate', methods=['GET', 'POST'])
def renegotiate(request_id):
    user_id = session.get('user_id')
    if user_id is None:
        flash('User not logged in.', 'error')
        return redirect(url_for('login'))  # Redirect to login if user is not logged in
    
    ad_request = AdRequest.query.get_or_404(request_id)
    if ad_request.influencer_name != User.query.get(user_id).username:
        flash('You do not have permission to renegotiate this request.', 'error')
        return redirect(url_for('iprofile'))
    
    if request.method == 'POST':
        # Process the form data
        # Example: Update ad_request with new values from the form
        ad_request.budget = request.form['new_budget']
        ad_request.status = 'renegotiate'
        db.session.commit()  # Save changes to the database
        
        flash('Renegotiation request submitted successfully.', 'success')
        return redirect(url_for('sprofile'))
    
    return render_template('renegotiate.html', ad_request=ad_request, id=request_id)

###################################################################

@app.route("/sprofile",methods=['GET','POST'])
@login_required
def sprofile():
    user_id = session.get('user_id')
    if not user_id:
        return render_template('landing_page.html')

    user = User.query.get_or_404(user_id)
    if user.role == 'influencer':
        return redirect(url_for('iprofile'))

    
    if 'user_id' in session:
        sponsor_id = session['user_id']
        # Fetch sponsor data from the database
        sponsor = User.query.filter_by(id=sponsor_id, role='sponsor').first()
        if sponsor:
            # active_campaigns = Campaign.query.filter_by(status='planning', user_id=sponsor_id).all()
            new_requests = AdRequest.query.filter_by(status='NIL' , user_id=sponsor_id).all()

            active_campaigns = Campaign.query.filter_by( user_id=sponsor_id).all()
            sponsor_profile_data = {
                'username':sponsor.username,
                'name': sponsor.company_name,
                'category':sponsor.category,
                'active_campaigns': [{'id': campaign.id, 'name': campaign.campaign_name, 'progress': campaign.progress} for campaign in active_campaigns],
                'new_requests': [{'id': request.id, 'influencer_name': request.influencer_name, 'ad_details': request.ad_name} for request in new_requests]
                
            }

            return render_template('Sprofile.html', sponsor_profile=sponsor_profile_data)
        else:
            # Handle case where sponsor ID from session does not match any sponsor in the database
            return "Sponsor not found."
    else:
        # Handle case where sponsor is not logged in
        return "Please log in as a sponsor."
    

    
@app.route('/supdate_profile', methods=['GET','POST'])
@login_required
def supdate_profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('user_login'))

    user = User.query.get_or_404(user_id)
    if user.role != 'sponsor':
        return redirect(url_for('user_login'))

    user.username = request.form['username']
    user.company_name = request.form['company_name']
    user.category = request.form['category']

    db.session.commit()
    flash('Profile updated successfully!', 'success')
    
    return redirect(url_for('sprofile'))



@app.route('/sponsor/campaigns')
@login_required
def s_campaigns():
    # Fetch campaigns related to the logged-in user
    user_id = session.get('user_id')
    campaigns = Campaign.query.filter_by(user_id=user_id).all()
    return render_template('s_campaigns.html', campaigns=campaigns)


@app.route('/sponsor/stats')
@login_required
def sstats():
    return render_template('s_stats.html')

@app.route('/sponsor/find_sponsor',methods=['GET','POST'])
@login_required
def sfind():
    results2 = None
    if request.method == 'POST':
        search_query = request.form['search_query'].lower()
        
        # Search logic for users and campaigns
        users = User.query.filter(
            (User.role=='influencer')&
            ((User.username.ilike(f"%{search_query}%")) |
            (User.company_name.ilike(f"%{search_query}%")) |
            (User.name.ilike(f"%{search_query}%")) |
            (User.category.ilike(f"%{search_query}%")) |
            (User.niche.ilike(f"%{search_query}%"))
        )).all()
        
        campaigns = Campaign.query.filter(
            (Campaign.campaign_name.ilike(f"%{search_query}%")) |
            (Campaign.category.ilike(f"%{search_query}%")) |
            (Campaign.products.ilike(f"%{search_query}%")) |
            (Campaign.goals.ilike(f"%{search_query}%"))
        ).all()
        
        results2 = {
            'users': users,
            'campaigns': campaigns
        }
    return render_template('f_sponsor.html',results2=results2)


@app.route('/add_campaign', methods=['GET', 'POST'])
@login_required
def add_campaign():
    if request.method == 'POST':
        user_id = session.get('user_id')
        campaign_name = request.form['campaign_name']
        category = request.form['category']
        budget = float(request.form['budget'])
        status = request.form['status']
        products = request.form['products']
        goals = request.form['goals']
        progress = int(request.form['progress'])
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()

        # Create new campaign
        new_campaign = Campaign(
            user_id=user_id,
            campaign_name=campaign_name,
            category=category,
            budget=budget,
            status=status,
            products=products,
            goals=goals,
            progress=progress,
            start_date=start_date,
            end_date=end_date
        )

        # Add campaign to the database
        db.session.add(new_campaign)
        db.session.commit()

        return redirect(url_for('s_campaigns'))  # Redirect to sponsor dashboard after campaign creation

    return render_template('add_campaign.html')

@app.route('/edit_campaign/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def edit_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)

    if request.method == 'POST':
        campaign.campaign_name = request.form['campaign_name']
        campaign.category = request.form['category']
        campaign.budget = float(request.form['budget'])
        campaign.status = request.form['status']
        campaign.products = request.form['products']
        campaign.goals = request.form['goals']
        campaign.progress = int(request.form['progress'])
        campaign.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d').date()
        campaign.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d').date()

        db.session.commit()
        return redirect(url_for('s_campaigns'))  # Redirect to sponsor dashboard after updating campaign

    return render_template('edit_campaign.html', campaign=campaign)



@app.route('/delete_campaign/<int:campaign_id>', methods=['POST','GET'])
@login_required
def delete_campaign(campaign_id):
    campaign = Campaign.query.get_or_404(campaign_id)
    db.session.delete(campaign)
    db.session.commit()  # Commit the deletion to the database
    flash('Campaign deleted successfully!', 'success')
    return redirect(url_for('s_campaigns'))


@app.route('/add_ad_request/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
def add_ad_request(campaign_id):
    if request.method == 'POST':
        ad_name = request.form['ad_name']
        description = request.form['description']
        budget = float(request.form['budget'])
        goal = request.form['goal']
        influencer_name = request.form['influencer_name']
        status = "NIL"
        user_id=session.get('user_id')
        new_ad_request = AdRequest(
            campaign_id=campaign_id,
            ad_name=ad_name,
            description=description,
            budget=budget,
            goal=goal,
            influencer_name=influencer_name,
            status=status,
            user_id=user_id
        )

        db.session.add(new_ad_request)
        db.session.commit()
        flash('Ad request created successfully!', 'success')
        return redirect(url_for('s_campaigns'))    
    return render_template('add_ad_request.html', campaign_id=campaign_id)

@app.route('/view_ad_requests/<int:campaign_id>', methods=['GET','POST'])
@login_required
def view_ad_requests(campaign_id):
    c = Campaign.query.get_or_404(campaign_id)  # Use campaign_id here
    ad = AdRequest.query.filter_by(campaign_id=campaign_id).all()
    return render_template('view_ad_request.html', campaign=c, ad_requests=ad)


@app.route('/edit_ad_request/<int:ad_request_id>', methods=['POST'])
@login_required
def edit_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    ad_request.ad_name = request.form['ad_name']
    ad_request.description = request.form['description']
    ad_request.budget = float(request.form['budget'])
    ad_request.goal = request.form['goal']
    ad_request.influencer_name = request.form['influencer_name']
    ad_request.status = "NIL"

    db.session.commit()
    flash('Ad request updated successfully!', 'success')
    return redirect(url_for('view_ad_requests', campaign_id=ad_request.campaign_id))

## Delete Ad Request
@app.route('/delete_ad_request/<int:ad_request_id>', methods=['POST'])
@login_required
def delete_ad_request(ad_request_id):
    ad_request = AdRequest.query.get_or_404(ad_request_id)
    campaign_id = ad_request.campaign_id
    db.session.delete(ad_request)
    db.session.commit()  # Commit the deletion to the database
    flash('Ad request deleted successfully!', 'success')
    return redirect(url_for('view_ad_requests', campaign_id=campaign_id))







## Admin DashBoard

@app.route('/admin_dash')
@login_required
def admin_dash():
    users = User.query.filter(~User.flagged.any(),User.role != 'admin').all()
    flagged_users = FlaggedUser.query.all()
    
    # Fetch flagged campaigns as needed (replace with your actual logic)
    flagged_campaigns = []  

    # Fetch ongoing campaigns and their progress
    campaigns = Campaign.query.all()
    return render_template('admin_dash.html', users=users, flagged_users=flagged_users, flagged_campaigns=flagged_campaigns, campaigns=campaigns)

@app.route('/flag_user/<int:user_id>', methods=['POST'])
@login_required
def flag_user(user_id):
    user = User.query.get(user_id)
    if user:
        # Check if the user is already flagged
        flagged_user = FlaggedUser.query.filter_by(user_id=user_id).first()
        if not flagged_user:
            new_flagged_user = FlaggedUser(user_id=user.id, username=user.username, role=user.role)
            db.session.add(new_flagged_user)
            db.session.commit()
            flash('User has been flagged successfully.', 'success')
        else:
            flash('User is already flagged.', 'warning')
    return redirect(url_for('admin_dash'))

@app.route('/unflag_user/<int:user_id>', methods=['POST'])
@login_required
def unflag_user(user_id):
    flagged_user = FlaggedUser.query.filter_by(user_id=user_id).first()
    if flagged_user:
        db.session.delete(flagged_user)
        db.session.commit()
        flash('User has been unflagged successfully.', 'success')
    return redirect(url_for('admin_dash'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    flagged_user = FlaggedUser.query.filter_by(user_id=user_id).first()
    
    if flagged_user:
        user = User.query.get(user_id)
        campaigns = Campaign.query.filter_by(user_id=flagged_user.user_id).all()

        # Delete associated campaigns
        for campaign in campaigns:
            db.session.delete(campaign)
        
        # Delete the flagged user and the actual user
        db.session.delete(flagged_user)
        db.session.delete(user)
        db.session.commit()

        flash('Flagged user has been deleted successfully.', 'success')
    else:
        flash('User must be flagged before deletion.', 'warning')
    
    return redirect(url_for('admin_dash'))



