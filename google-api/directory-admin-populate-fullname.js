/**
 * Updates all users in Google Workspace with their full name in the Dogfood.Fullname custom attribute.
 * This attribute can then be mapped in SAML configurations for Fleet integration.
 */
function updateFullnames() {
  const users = AdminDirectory.Users.list({customer: 'my_customer'}).users;
  
  users.forEach(user => {
    const fullName = `${user.name.givenName} ${user.name.familyName}`.trim();
    
    // Update custom schema using Dogfood category and Fullname attribute
    const customSchemas = {
      Dogfood: {
        Fullname: fullName
      }
    };
    
    try {
      AdminDirectory.Users.update(
        {customSchemas: customSchemas},
        user.primaryEmail
      );
      console.log(`Updated ${user.primaryEmail} with full name: ${fullName}`);
    } catch (error) {
      console.log(`Error updating ${user.primaryEmail}: ${error}`);
    }
  });
}

/**
 * Creates a daily trigger to run the updateFullnames function.
 * Run this function once to set up the automatic daily updates.
 */
function createTrigger() {
  // Check if trigger already exists
  const triggers = ScriptApp.getProjectTriggers();
  const triggerExists = triggers.some(trigger => 
    trigger.getHandlerFunction() === 'updateFullnames' && 
    trigger.getEventType() === ScriptApp.EventType.CLOCK
  );
  
  // Only create a new trigger if one doesn't already exist
  if (!triggerExists) {
    ScriptApp.newTrigger('updateFullnames')
      .timeBased()
      .everyDays(1)
      .create();
    console.log('Daily trigger created successfully');
  } else {
    console.log('Daily trigger already exists');
  }
}